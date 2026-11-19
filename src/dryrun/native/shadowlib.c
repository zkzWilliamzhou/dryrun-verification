/*
 * shadowlib.c - LD_PRELOAD file-operation shim for dryrun's trace engine.
 *
 * PROTOCOL
 * --------
 * The Python driver sets three environment variables before spawning the
 * traced command with LD_PRELOAD pointing at this library:
 *
 *   DRYRUN_SHADOW    Absolute root of the "shadow tree". Every intercepted
 *                    write-class operation is redirected to the matching
 *                    path under this root (copy-on-write).
 *   DRYRUN_TRACE_FD  Write end of a pipe (decimal fd number). One line per
 *                    intercepted operation: "OP|arg1|arg2\n".
 *   DRYRUN_CWD       Absolute working directory of the traced command, the
 *                    base used to resolve relative paths.
 *
 * If any variable is missing (or a required libc symbol cannot be resolved)
 * the shim switches to pure passthrough mode: every intercepted function
 * forwards to the real libc implementation, so preloading the library by
 * accident can never break a program.
 *
 * SAFETY MODEL
 * ------------
 * - The real file system is never modified. Write opens go to a
 *   copy-on-write copy under DRYRUN_SHADOW; unlink/rmdir leave a
 *   "<path>.dryrun-tombstone" marker instead of deleting anything; rename,
 *   mkdir, chmod, truncate, link, symlink and mknod operate on shadow
 *   copies only.
 * - Fail-closed: if a shadow operation fails (permissions, disk full,
 *   internal error) the intercepted call returns an error (usually EIO)
 *   rather than falling back to the real path. The real path is only ever
 *   touched by read-only opens and by the passthrough zones below.
 * - Only an exact whitelist of character devices (/dev/null, /dev/zero,
 *   /dev/full, /dev/stdin, /dev/stdout, /dev/stderr, /dev/tty) is ever
 *   passed through for writing (logged as a NOTE_DEV_WRITE line);
 *   everything else under /dev (e.g. /dev/shm) is virtualized into the
 *   shadow tree. /proc and /sys pass through for reads only; write-class
 *   operations there are virtualized and logged as NOTE_PSEUDO_WRITE.
 *   Path aliases such as /proc/self/root/... resolve to their canonical
 *   destination first and can never reach the passthrough whitelist.
 * - Symlinks stored inside the shadow tree carry targets rewritten so
 *   they can only resolve within the tree, and every real call that
 *   mutates a shadow path is guarded by O_NOFOLLOW plus a resolved
 *   containment check (dr_inside_shadow): a shadow path that would
 *   resolve outside the tree fails closed with EIO/ELOOP rather than
 *   letting the kernel follow it out.
 * - Read-only opens pass through and are only recorded in an internal
 *   fd table so that fchmod/ftruncate/fchown/futimens on them can be
 *   virtualized. Fds opened for writing always refer to a shadow copy.
 * - chdir is tracked lexically. When the target directory exists only in
 *   the shadow tree (this run created it), the chdir is virtualized: the
 *   tracked cwd and the DRYRUN_CWD environment variable are updated so
 *   that later relative operations (including those of exec'd children)
 *   resolve against the simulated location, and relative read-only opens
 *   are re-based onto the tracked cwd explicitly.
 * - One global pthread mutex guards all shim state (fd table, tracked
 *   cwd, and the shadow operations themselves). An atfork handler keeps
 *   the mutex usable after fork(). Log lines are emitted with raw
 *   write() and are best effort.
 * - Known limits: raw syscalls, static binaries, and libc-internal calls
 *   that bypass the PLT (e.g. mkstemp) are not intercepted.
 */
#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Path buffers: a shadow path is the shadow root plus a real path. */
#define DR_BUFSZ 8192
/* Log line buffer: op + two paths. */
#define DR_LOGBUFSZ (2 * DR_BUFSZ + 64)
/* Cap a written log line at PIPE_BUF so concurrent writers to the trace
 * pipe never interleave partial lines. */
#define DR_LOG_MAX 4096
/* Fixed fd table size; fds at or above it are simply not tracked. */
#define DR_FD_SLOTS 4096
/* Copy loop chunk and materialization caps (fail-closed beyond these). */
#define DR_COPY_CHUNK 65536
#define DR_MAX_ENTRIES 32768
#define DR_MAX_DEPTH 64
#define DR_MAX_BYTES (256LL * 1024LL * 1024LL)

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1U << 1)
#endif
#ifndef RENAME_WHITEOUT
#define RENAME_WHITEOUT (1U << 2)
#endif

/* ------------------------------------------------------------------ */
/* Global state                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    char *path;   /* real absolute path of the opened file, or NULL */
    int shadowed; /* nonzero when the fd refers to the shadow copy */
} dr_fdent;

/* Counters bounding recursive materialization (fail-closed on overflow). */
typedef struct {
    long entries;
    long long bytes;
} dr_limits;

static pthread_mutex_t dr_lock = PTHREAD_MUTEX_INITIALIZER;
static int dr_active;          /* zero: passthrough mode */
static char dr_shadow[DR_BUFSZ]; /* shadow root, no trailing slash */
static size_t dr_shadow_len;
static int dr_trace_fd = -1;
static char dr_cwd[DR_BUFSZ];  /* tracked cwd, absolute, lexical */
static int dr_cwd_valid = 1;
static int dr_cwd_virtual;     /* real cwd differs from tracked cwd */
static dr_fdent dr_fds[DR_FD_SLOTS];

/* ------------------------------------------------------------------ */
/* Real libc functions                                                 */
/* ------------------------------------------------------------------ */

static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static FILE *(*real_fopen)(const char *, const char *);
static FILE *(*real_fdopen)(int, const char *);
static int (*real_close)(int);
static int (*real_fclose)(FILE *);
static int (*real_fileno)(FILE *);
static int (*real_unlink)(const char *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_rename)(const char *, const char *);
static int (*real_renameat)(int, const char *, int, const char *);
static int (*real_renameat2)(int, const char *, int, const char *, unsigned int);
static int (*real_mkdir)(const char *, mode_t);
static int (*real_mkdirat)(int, const char *, mode_t);
static int (*real_rmdir)(const char *);
static int (*real_chmod)(const char *, mode_t);
static int (*real_fchmod)(int, mode_t);
static int (*real_fchmodat)(int, const char *, mode_t, int);
static int (*real_symlink)(const char *, const char *);
static int (*real_symlinkat)(const char *, int, const char *);
static int (*real_link)(const char *, const char *);
static int (*real_linkat)(int, const char *, int, const char *, int);
static int (*real_truncate)(const char *, off_t);
static int (*real_ftruncate)(int, off_t);
static int (*real_mknod)(const char *, mode_t, dev_t);
static int (*real_mknodat)(int, const char *, mode_t, dev_t);
static int (*real_mkstemp)(char *);
static int (*real_mkostemp)(char *, int);
static int (*real_mkstemps)(char *, int);
static int (*real_mkostemps)(char *, int, int);
static char *(*real_mkdtemp)(char *);
static int (*real_dup)(int);
static int (*real_dup2)(int, int);
static int (*real_dup3)(int, int, int);
static int (*real_chdir)(const char *);
static int (*real_fchdir)(int);
static int (*real_utimensat)(int, const char *, const struct timespec *, int);
static int (*real_futimens)(int, const struct timespec *);
static int (*real_chown)(const char *, uid_t, gid_t);
static int (*real_lchown)(const char *, uid_t, gid_t);
static int (*real_fchown)(int, uid_t, gid_t);
static int (*real_fchownat)(int, const char *, uid_t, gid_t, int);
static int (*real_stat)(const char *, struct stat *);
static int (*real_lstat)(const char *, struct stat *);
static int (*real_fstatat)(int, const char *, struct stat *, int);
static int (*real_access)(const char *, int);
static int (*real_faccessat)(int, const char *, int, int);

/* ------------------------------------------------------------------ */
/* Initialization                                                      */
/* ------------------------------------------------------------------ */

static void dr_init_body(void);
static void dr_resolve(void)
{
    real_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    real_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
    real_fopen = (FILE * (*)(const char *, const char *)) dlsym(RTLD_NEXT, "fopen");
    real_fdopen = (FILE * (*)(int, const char *)) dlsym(RTLD_NEXT, "fdopen");
    real_close = (int (*)(int))dlsym(RTLD_NEXT, "close");
    real_fclose = (int (*)(FILE *))dlsym(RTLD_NEXT, "fclose");
    real_fileno = (int (*)(FILE *))dlsym(RTLD_NEXT, "fileno");
    real_unlink = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
    real_unlinkat = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "unlinkat");
    real_rename = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "rename");
    real_renameat = (int (*)(int, const char *, int, const char *))dlsym(
        RTLD_NEXT, "renameat");
    real_renameat2 = (int (*)(int, const char *, int, const char *, unsigned int))
        dlsym(RTLD_NEXT, "renameat2");
    real_mkdir = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "mkdir");
    real_mkdirat = (int (*)(int, const char *, mode_t))dlsym(RTLD_NEXT, "mkdirat");
    real_rmdir = (int (*)(const char *))dlsym(RTLD_NEXT, "rmdir");
    real_chmod = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "chmod");
    real_fchmod = (int (*)(int, mode_t))dlsym(RTLD_NEXT, "fchmod");
    real_fchmodat = (int (*)(int, const char *, mode_t, int))dlsym(
        RTLD_NEXT, "fchmodat");
    real_symlink = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "symlink");
    real_symlinkat = (int (*)(const char *, int, const char *))dlsym(
        RTLD_NEXT, "symlinkat");
    real_link = (int (*)(const char *, const char *))dlsym(RTLD_NEXT, "link");
    real_linkat = (int (*)(int, const char *, int, const char *, int))dlsym(
        RTLD_NEXT, "linkat");
    real_truncate = (int (*)(const char *, off_t))dlsym(RTLD_NEXT, "truncate");
    real_ftruncate = (int (*)(int, off_t))dlsym(RTLD_NEXT, "ftruncate");
    real_mknod = (int (*)(const char *, mode_t, dev_t))dlsym(RTLD_NEXT, "mknod");
    real_mknodat = (int (*)(int, const char *, mode_t, dev_t))dlsym(
        RTLD_NEXT, "mknodat");
    real_mkstemp = (int (*)(char *))dlsym(RTLD_NEXT, "mkstemp");
    real_mkostemp = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkostemp");
    real_mkstemps = (int (*)(char *, int))dlsym(RTLD_NEXT, "mkstemps");
    real_mkostemps = (int (*)(char *, int, int))dlsym(RTLD_NEXT, "mkostemps");
    real_mkdtemp = (char *(*)(char *))dlsym(RTLD_NEXT, "mkdtemp");
    real_dup = (int (*)(int))dlsym(RTLD_NEXT, "dup");
    real_dup2 = (int (*)(int, int))dlsym(RTLD_NEXT, "dup2");
    real_dup3 = (int (*)(int, int, int))dlsym(RTLD_NEXT, "dup3");
    real_chdir = (int (*)(const char *))dlsym(RTLD_NEXT, "chdir");
    real_fchdir = (int (*)(int))dlsym(RTLD_NEXT, "fchdir");
    real_utimensat = (int (*)(int, const char *, const struct timespec *, int))dlsym(
        RTLD_NEXT, "utimensat");
    real_futimens = (int (*)(int, const struct timespec *))dlsym(
        RTLD_NEXT, "futimens");
    real_chown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
    real_lchown = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "lchown");
    real_fchown = (int (*)(int, uid_t, gid_t))dlsym(RTLD_NEXT, "fchown");
    real_fchownat = (int (*)(int, const char *, uid_t, gid_t, int))dlsym(
        RTLD_NEXT, "fchownat");
    real_stat = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "stat");
    real_lstat = (int (*)(const char *, struct stat *))dlsym(
        RTLD_NEXT, "lstat");
    real_fstatat = (int (*)(int, const char *, struct stat *, int))dlsym(
        RTLD_NEXT, "fstatat");
    real_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
    real_faccessat = (int (*)(int, const char *, int, int))dlsym(
        RTLD_NEXT, "faccessat");
}

/* The shim is only enabled when every symbol on this list resolves. */
static int dr_required_present(void)
{
    return real_open && real_openat && real_fopen && real_fdopen && real_close
        && real_fclose && real_fileno && real_unlink && real_unlinkat
        && real_rename && real_renameat && real_mkdir && real_mkdirat
        && real_rmdir && real_chmod && real_fchmod && real_fchmodat
        && real_symlink && real_link && real_truncate && real_ftruncate
        && real_dup && real_dup2 && real_chdir && real_lstat;
}

static void dr_atfork_prepare(void)
{
    pthread_mutex_lock(&dr_lock);
}

static void dr_atfork_release(void)
{
    pthread_mutex_unlock(&dr_lock);
}

/*
 * One-time initialization. Runs either from the library constructor or
 * lazily from any interceptor: other libraries' constructors may call
 * open/fopen before our own constructor has run, so no interceptor may
 * rely on constructor-time initialization.
 *
 * The real libc pointers are always resolved, even in passthrough mode,
 * so an accidental LD_PRELOAD can never crash the host program.
 */
static pthread_once_t dr_once = PTHREAD_ONCE_INIT;

static void dr_ensure_init(void)
{
    pthread_once(&dr_once, dr_init_body);
}

__attribute__((constructor))
static void dr_init(void)
{
    dr_ensure_init();
}

static void dr_init_body(void)
{
    const char *shadow = getenv("DRYRUN_SHADOW");
    const char *fdstr = getenv("DRYRUN_TRACE_FD");
    const char *cwd = getenv("DRYRUN_CWD");
    char *end = NULL;
    long fd;

    dr_resolve();
    if (!dr_required_present())
        return; /* cannot intercept safely: stay in passthrough mode */
    if (!shadow || !fdstr || !cwd)
        return; /* no trace context: passthrough mode */
    if (shadow[0] != '/' || cwd[0] != '/')
        return;
    fd = strtol(fdstr, &end, 10);
    if (end == fdstr || *end != '\0' || fd < 0 || fd > INT_MAX)
        return;

    /* Strip trailing slashes from the shadow root (keep a bare "/"). */
    size_t len = strlen(shadow);
    while (len > 1 && shadow[len - 1] == '/')
        len--;
    if (len >= sizeof(dr_shadow) || strlen(cwd) >= sizeof(dr_cwd))
        return;
    memcpy(dr_shadow, shadow, len);
    dr_shadow[len] = '\0';
    {
        /* Prefer the fully resolved shadow root so containment checks
         * against realpath() results keep matching even when the temp
         * dir goes through a symlink (e.g. TMPDIR=/link/to/tmp). */
        char rp[DR_BUFSZ];

        if (realpath(dr_shadow, rp) != NULL && strcmp(rp, "/") != 0
            && strlen(rp) < sizeof(dr_shadow))
            snprintf(dr_shadow, sizeof(dr_shadow), "%s", rp);
    }
    dr_shadow_len = strlen(dr_shadow);
    snprintf(dr_cwd, sizeof(dr_cwd), "%s", cwd);
    dr_trace_fd = (int)fd;
    dr_cwd_valid = 1;
    dr_active = 1;
    /* The trace pipe's read end may go away before an orphaned child
     * logs a line; ignore SIGPIPE so that write() fails with EPIPE
     * instead of killing the traced process. */
    signal(SIGPIPE, SIG_IGN);
    {
        /* Children exec'd after a (possibly virtual) chdir inherit an
         * updated DRYRUN_CWD but the parent's real cwd: detect that
         * mismatch so relative read-only opens are re-based. */
        char cur[DR_BUFSZ];

        if (getcwd(cur, sizeof(cur)) == NULL || strcmp(cur, dr_cwd) != 0)
            dr_cwd_virtual = 1;
    }
    pthread_atfork(dr_atfork_prepare, dr_atfork_release, dr_atfork_release);
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/* Best-effort log line; never blocks correctness, never recurses. */
static void dr_log2(const char *op, const char *a, const char *b)
{
    char buf[DR_LOGBUFSZ];
    int n;

    if (dr_trace_fd < 0)
        return;
    if (b)
        n = snprintf(buf, sizeof(buf), "%s|%s|%s\n", op, a, b);
    else
        n = snprintf(buf, sizeof(buf), "%s|%s\n", op, a);
    if (n <= 0)
        return;
    if ((size_t)n >= sizeof(buf)) {
        n = (int)sizeof(buf) - 1;
        buf[n - 1] = '\n';
    }
    if (n > DR_LOG_MAX) {
        n = DR_LOG_MAX;
        buf[n - 1] = '\n'; /* keep the line atomic and newline-terminated */
    }
    ssize_t rc = write(dr_trace_fd, buf, (size_t)n);
    (void)rc;
}

/*
 * Character devices that are safe (and useful) to pass through even for
 * writing: writing to one can never modify the file system. The match is
 * an exact strcmp on the path as the caller spelled it (normalized) and
 * on its fully resolved canon - never a prefix - so aliases such as
 * /proc/self/root/dev/null or writable directories such as /dev/shm can
 * never sneak a real write past this table. /proc and /sys are NOT in
 * the table: reads pass through unconditionally, but write-class
 * operations there are virtualized into the shadow tree.
 */
static int dr_is_passthrough(const char *path)
{
    static const char *const devices[] = {
        "/dev/null",  "/dev/zero",  "/dev/full", "/dev/stdin",
        "/dev/stdout", "/dev/stderr", "/dev/tty",  NULL,
    };
    int i;

    if (!path)
        return 0;
    for (i = 0; devices[i]; i++)
        if (strcmp(path, devices[i]) == 0)
            return 1;
    return 0;
}

/* Write into a kernel pseudo filesystem that got virtualized into the
 * shadow tree (the real /proc or /sys entry was never touched). */
static int dr_is_pseudo_write(const char *canon)
{
    return !strncmp(canon, "/proc/", 6) || !strcmp(canon, "/proc")
        || !strncmp(canon, "/sys/", 5) || !strcmp(canon, "/sys");
}

/* Lexically normalize an absolute path (collapse //, ., and ..). */
static int dr_normalize(const char *src, char *dst, size_t dstsz)
{
    const char *comp;

    if (!src || src[0] != '/') {
        errno = EINVAL;
        return -1;
    }
    dst[0] = '/';
    dst[1] = '\0';
    comp = src;
    while (*comp) {
        const char *start;
        size_t clen;
        while (*comp == '/')
            comp++;
        if (!*comp)
            break;
        start = comp;
        while (*comp && *comp != '/')
            comp++;
        clen = (size_t)(comp - start);
        if (clen == 1 && start[0] == '.')
            continue;
        if (clen == 2 && start[0] == '.' && start[1] == '.') {
            char *slash = strrchr(dst, '/');
            if (slash == dst)
                dst[1] = '\0';
            else if (slash)
                *slash = '\0';
            continue;
        }
        if (strcmp(dst, "/") != 0) {
            if (strlen(dst) + 1 + clen >= dstsz)
                goto overflow;
            strcat(dst, "/");
        }
        if (strlen(dst) + clen >= dstsz)
            goto overflow;
        strncat(dst, start, clen);
    }
    return 0;
overflow:
    errno = ENAMETOOLONG;
    return -1;
}

/* Split an absolute path into dirname and final component. */
static void dr_split(const char *path, char *dir, size_t dirsz, char *base,
                     size_t basesz)
{
    const char *slash = strrchr(path, '/');
    size_t dlen;

    if (!slash || slash == path) {
        snprintf(dir, dirsz, "/");
        snprintf(base, basesz, "%s", slash ? slash + 1 : path);
        return;
    }
    dlen = (size_t)(slash - path);
    if (dlen >= dirsz)
        dlen = dirsz - 1;
    memcpy(dir, path, dlen);
    dir[dlen] = '\0';
    snprintf(base, basesz, "%s", slash + 1);
}

/*
 * Resolve a final symlink component chain (bounded). Used when the full
 * realpath() failed because the ultimate target does not exist yet, which
 * is exactly the O_CREAT case where the real open would follow the link.
 */
static void dr_chase(const char *in, char *out, size_t outsz)
{
    char cur[DR_BUFSZ], target[DR_BUFSZ], dir[DR_BUFSZ], tmp[DR_BUFSZ];
    struct stat st;
    int i;

    snprintf(cur, sizeof(cur), "%s", in);
    for (i = 0; i < 8; i++) {
        ssize_t n;
        if (real_lstat(cur, &st) != 0 || !S_ISLNK(st.st_mode))
            break;
        n = readlink(cur, target, sizeof(target) - 1);
        if (n <= 0)
            break;
        target[n] = '\0';
        if (target[0] == '/') {
            if (dr_normalize(target, cur, sizeof(cur)) != 0)
                break;
        } else {
            dr_split(cur, dir, sizeof(dir), tmp, sizeof(tmp));
            if (snprintf(tmp, sizeof(tmp), "%s/%s", dir, target) >= (int)sizeof(tmp))
                break;
            if (dr_normalize(tmp, cur, sizeof(cur)) != 0)
                break;
        }
    }
    snprintf(out, outsz, "%s", cur);
}

/*
 * Canonicalize a lexically absolute path for shadow mapping. With
 * follow_final, symlinks in the last component are resolved (open/chmod/
 * truncate semantics); without it, only the parent chain is resolved
 * (mkdir/unlink/rename semantics, which act on the name itself).
 */
static void dr_canon(const char *abs, int follow_final, char *out, size_t outsz)
{
    char rp[DR_BUFSZ], dir[DR_BUFSZ], base[DR_BUFSZ];
    int n;

    if (follow_final && realpath(abs, rp) != NULL) {
        snprintf(out, outsz, "%s", rp);
        return;
    }
    dr_split(abs, dir, sizeof(dir), base, sizeof(base));
    if (base[0] && realpath(dir, rp) != NULL) {
        if (strcmp(rp, "/") == 0)
            n = snprintf(out, outsz, "/%s", base);
        else
            n = snprintf(out, outsz, "%s/%s", rp, base);
        if (n > 0 && (size_t)n < outsz) {
            if (follow_final)
                dr_chase(out, out, outsz);
            return;
        }
    }
    snprintf(out, outsz, "%s", abs);
}

/* Map a real absolute path to its shadow-tree counterpart. */
static int dr_shadow_path(const char *real_abs, char *out, size_t outsz)
{
    int n = snprintf(out, outsz, "%s%s", dr_shadow, real_abs);

    if (n < 0 || (size_t)n >= outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* Containment test: a resolved path must be the shadow root or below. */
static int dr_is_shadow_prefix(const char *resolved)
{
    size_t n = dr_shadow_len;

    return strncmp(resolved, dr_shadow, n) == 0
        && (resolved[n] == '\0' || resolved[n] == '/');
}

/*
 * Containment assertion for every real call about to mutate a shadow
 * path. The fully resolved path (realpath follows any symlinks embedded
 * in the shadow path) must stay inside the shadow root; a path whose
 * final component does not resolve (it is about to be created, or the
 * caller will not follow it) is judged by its resolved parent instead.
 * realpath is not an intercepted symbol and glibc implements it with
 * internal syscalls, so it cannot reenter the shim and is safe to call
 * while dr_lock is held. Fail-closed: -1 with errno = EIO.
 */
static int dr_inside_shadow(const char *shadow_path)
{
    char rp[DR_BUFSZ], dir[DR_BUFSZ], base[DR_BUFSZ];

    if (realpath(shadow_path, rp) == NULL) {
        /* Missing final component (O_CREAT/mkdir) or a final symlink the
         * caller will not follow: verify the parent chain instead. */
        dr_split(shadow_path, dir, sizeof(dir), base, sizeof(base));
        if (!base[0] || realpath(dir, rp) == NULL)
            goto outside;
    }
    if (dr_is_shadow_prefix(rp))
        return 0;
outside:
    errno = EIO;
    return -1;
}

/*
 * Compute the target actually stored for a symlink whose real path is
 * link_abs (its shadow copy will live at dr_shadow + link_abs). The
 * stored target is always an absolute, lexically normalized path inside
 * the shadow tree pointing at the shadow copy of the link's real
 * destination: absolute targets are rebased onto the shadow root, and
 * relative targets are resolved against the link's parent first. This
 * guarantees the kernel can never follow a shadow symlink out of the
 * tree, no matter how links and ".." climbs are chained. Returns 0 on
 * success, -1 with errno set (EINVAL/ENAMETOOLONG) otherwise.
 */
static int dr_symlink_shadow_target(const char *target, const char *link_abs,
                                    char *out, size_t outsz)
{
    char dir[DR_BUFSZ], base[DR_BUFSZ], comb[DR_BUFSZ], norm[DR_BUFSZ];
    int n;

    if (!target || !target[0]) {
        errno = EINVAL;
        return -1;
    }
    dr_split(link_abs, dir, sizeof(dir), base, sizeof(base));
    if (target[0] == '/') {
        if (dr_normalize(target, norm, sizeof(norm)) != 0)
            return -1;
        if (dr_is_shadow_prefix(norm))
            goto keep; /* already aims inside the shadow tree */
        return dr_shadow_path(norm, out, outsz);
    }
    /* Relative target: resolve it against the link's parent directory,
     * then rebase the destination onto the shadow root. */
    n = snprintf(comb, sizeof(comb), "%s/%s", dir, target);
    if (n < 0 || (size_t)n >= sizeof(comb))
        goto toolong;
    if (dr_normalize(comb, norm, sizeof(norm)) != 0)
        return -1;
    return dr_shadow_path(norm, out, outsz);
keep:
    n = snprintf(out, outsz, "%s", norm);
    if (n < 0 || (size_t)n >= outsz)
        goto toolong;
    return 0;
toolong:
    errno = ENAMETOOLONG;
    return -1;
}

static int dr_exists(const char *path)
{
    struct stat st;

    return real_lstat(path, &st) == 0;
}

static int dr_isdir(const char *path)
{
    struct stat st;

    return real_lstat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Simulated-view selectors for the stat family. */
#define DR_VIEW_SHADOW 0 /* use the shadow copy at *shadow          */
#define DR_VIEW_REAL 1   /* use the real entry                       */
#define DR_VIEW_GONE 2   /* tombstoned: report ENOENT                */

/*
 * Pick which copy of canon represents the simulated state: a live
 * shadow copy (created or materialized during this run) wins, a
 * tombstone hides the real entry, anything else is the real entry.
 * Lock-free on purpose: stat wrappers never take dr_lock, so they can
 * never deadlock against a shadow operation in flight.
 */
static int dr_view(const char *canon, char *shadow, size_t shadowsz)
{
    char tomb[DR_BUFSZ + 32];

    if (dr_shadow_path(canon, shadow, shadowsz) != 0)
        return DR_VIEW_REAL;
    if (dr_exists(shadow))
        return DR_VIEW_SHADOW;
    if (dr_shadow_path(canon, tomb, sizeof(tomb) - 24) == 0) {
        strcat(tomb, ".dryrun-tombstone");
        if (dr_exists(tomb))
            return DR_VIEW_GONE;
    }
    return DR_VIEW_REAL;
}

/*
 * Emptiness of a directory in the SIMULATED state: real entries count
 * unless they carry a tombstone, shadow entries count unless they are
 * tombstone markers. This is what makes "rm -rf dir" work: by the time
 * rmdir(dir) runs, every real child has a tombstone in the shadow copy
 * of dir, so the directory is simulated-empty.
 */
static int dr_is_tombstone_name(const char *name)
{
    size_t len = strlen(name);

    return len > 17 && !strcmp(name + len - 17, ".dryrun-tombstone");
}

static int dr_simulated_nonempty(const char *real_dir, const char *shadow_dir)
{
    DIR *d;
    struct dirent *e;

    if (dr_isdir(real_dir)) {
        d = opendir(real_dir);
        if (!d)
            return 1; /* exists but unreadable: refuse to delete */
        while ((e = readdir(d)) != NULL) {
            char tomb[DR_BUFSZ + 32];
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            if (snprintf(tomb, sizeof(tomb), "%s/%s.dryrun-tombstone",
                         shadow_dir, e->d_name)
                >= (int)sizeof(tomb)) {
                closedir(d);
                return 1; /* path too long: refuse to judge the dir empty */
            }
            if (!dr_exists(tomb)) {
                closedir(d);
                return 1; /* real entry without a tombstone */
            }
        }
        closedir(d);
    }
    d = opendir(shadow_dir);
    if (!d)
        return 0; /* no shadow dir: only real entries mattered */
    while ((e = readdir(d)) != NULL) {
        char real_entry[DR_BUFSZ + 32];

        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        if (dr_is_tombstone_name(e->d_name))
            continue;
        /* A shadow entry whose real counterpart exists is a materialized
         * mirror: the real scan above already judged it (tombstone check).
         * Only shadow-only entries count as new content created during
         * this run. */
        if (snprintf(real_entry, sizeof(real_entry), "%s/%s", real_dir,
                     e->d_name)
                >= (int)sizeof(real_entry)) {
            closedir(d);
            return 1; /* path too long: refuse to judge the dir empty */
        }
        if (dr_exists(real_entry))
            continue;
        closedir(d);
        return 1; /* live shadow entry created during this run */
    }
    closedir(d);
    return 0;
}

/* mkdir -p for the shadow parents of spath (spath is a mutable scratch). */
static int dr_ensure_parents(char *spath)
{
    char *p;
    char closed[DR_BUFSZ];
    struct stat st;

    /* Closed-sentinel: the engine drops <DRYRUN_SHADOW>/.dryrun-closed
     * into the shadow root right before tearing the tree down. Once it
     * is there, every shadow mutation fails closed so an orphaned child
     * cannot revive the tree (or push writes anywhere else). */
    if (snprintf(closed, sizeof(closed), "%s/.dryrun-closed", dr_shadow)
            < (int)sizeof(closed)
        && real_lstat(closed, &st) == 0) {
        errno = EIO;
        return -1;
    }
    for (p = spath + dr_shadow_len; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (real_mkdir(spath, 0755) != 0 && errno != EEXIST) {
            int saved = errno;
            *p = '/';
            errno = saved;
            return -1;
        }
        *p = '/';
    }
    return 0;
}

/* Resolve a path as the kernel would for openat(dirfd, path). */
static int dr_abspath_at(int dirfd, const char *path, char *out, size_t outsz)
{
    char tmp[DR_BUFSZ], link[64], target[DR_BUFSZ];
    ssize_t n;
    int w;

    if (!path || !path[0]) {
        errno = EINVAL;
        return -1;
    }
    if (path[0] == '/')
        return dr_normalize(path, out, outsz);
    if (dirfd == AT_FDCWD) {
        if (!dr_cwd_valid) {
            errno = EIO;
            return -1;
        }
        w = snprintf(tmp, sizeof(tmp), "%s/%s", dr_cwd, path);
    } else {
        snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);
        n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0) {
            errno = EIO;
            return -1;
        }
        target[n] = '\0';
        w = snprintf(tmp, sizeof(tmp), "%s/%s", target, path);
    }
    if (w < 0 || (size_t)w >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return dr_normalize(tmp, out, outsz);
}

static int dr_abspath(const char *path, char *out, size_t outsz);
static void dr_fd_set(int fd, const char *path, int shadowed);

/*
 * Path to hand to a real read-only open of a relative name: after a
 * virtual chdir the real working directory is stale, so the name must be
 * re-based onto the tracked cwd. Returns the original path, the rebased
 * buffer, or NULL with errno set when the base cannot be resolved.
 */
static const char *dr_read_base(const char *path, char *buf, size_t bufsz)
{
    if (!dr_cwd_virtual || !path || path[0] == '/')
        return path;
    if (dr_abspath(path, buf, bufsz) != 0) {
        errno = EIO;
        return NULL;
    }
    return buf;
}

/*
 * Best-effort read of an entry whose real open failed with ENOENT but
 * which may exist in the shadow tree. Returns the shadow fd (tracked
 * under its real name) or -1 with the caller's errno preserved.
 */
static int dr_open_shadow_read(int dirfd, const char *path, int flags,
                               mode_t mode)
{
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];
    int fd, saved = errno;

    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = saved;
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon)) {
        errno = saved;
        return -1;
    }
    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0
        || !dr_exists(shadow)) {
        pthread_mutex_unlock(&dr_lock);
        errno = saved;
        return -1;
    }
    fd = real_openat(AT_FDCWD, shadow, (flags & ~O_CREAT) | O_NOFOLLOW, mode);
    if (fd >= 0)
        dr_fd_set(fd, canon, 0);
    else
        errno = saved; /* keep the original ENOENT on failure */
    pthread_mutex_unlock(&dr_lock);
    return fd;
}

/* ------------------------------------------------------------------ */
/* fd table (all functions expect dr_lock to be held)                  */
/* ------------------------------------------------------------------ */

static void dr_fd_set(int fd, const char *path, int shadowed)
{
    if (fd < 0 || fd >= DR_FD_SLOTS)
        return; /* table full for this fd: it stays untracked */
    free(dr_fds[fd].path);
    dr_fds[fd].path = strdup(path);
    dr_fds[fd].shadowed = shadowed;
}

static void dr_fd_clear(int fd)
{
    if (fd < 0 || fd >= DR_FD_SLOTS)
        return;
    free(dr_fds[fd].path);
    dr_fds[fd].path = NULL;
    dr_fds[fd].shadowed = 0;
}

static void dr_fd_copy(int from, int to)
{
    if (from < 0 || from >= DR_FD_SLOTS || to < 0 || to >= DR_FD_SLOTS)
        return;
    free(dr_fds[to].path);
    dr_fds[to].path = dr_fds[from].path ? strdup(dr_fds[from].path) : NULL;
    dr_fds[to].shadowed = dr_fds[from].shadowed;
}

static int dr_fd_get(int fd, char *out, size_t outsz, int *shadowed)
{
    if (fd < 0 || fd >= DR_FD_SLOTS || !dr_fds[fd].path)
        return -1;
    if (snprintf(out, outsz, "%s", dr_fds[fd].path) >= (int)outsz)
        return -1;
    *shadowed = dr_fds[fd].shadowed;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Copy-on-write materialization                                       */
/* ------------------------------------------------------------------ */

static int dr_copy_file(const char *src, const char *dst, mode_t mode,
                        dr_limits *lim)
{
    char buf[DR_COPY_CHUNK];
    struct stat st;
    int in, out;
    ssize_t r;

    in = real_open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0)
        return -1;
    out = real_open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                    0600);
    if (out < 0) {
        int saved = errno;
        real_close(in);
        errno = saved;
        return -1;
    }
    if (fstat(in, &st) == 0) {
        lim->bytes += (long long)st.st_size;
        if (lim->bytes > DR_MAX_BYTES)
            goto too_big;
    }
    while ((r = read(in, buf, sizeof(buf))) > 0) {
        ssize_t off = 0;
        while (off < r) {
            ssize_t w = write(out, buf + off, (size_t)(r - off));
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto fail;
            }
            off += w;
        }
    }
    if (r < 0)
        goto fail;
    if (real_fchmod(out, mode) != 0)
        goto fail;
    real_close(in);
    real_close(out);
    return 0;
too_big:
    errno = EIO;
fail : {
    int saved = errno;
    real_close(in);
    real_close(out);
    errno = saved;
    return -1;
}
}

/* Recursively mirror real_abs into the shadow tree at shadow_abs. */
static int dr_materialize(const char *real_abs, const char *shadow_abs,
                          dr_limits *lim, int depth)
{
    struct stat st;
    DIR *d;
    struct dirent *e;
    char r2[DR_BUFSZ], s2[DR_BUFSZ];

    if (real_lstat(real_abs, &st) != 0)
        return -1;
    if (++lim->entries > DR_MAX_ENTRIES || depth > DR_MAX_DEPTH
        || lim->bytes > DR_MAX_BYTES) {
        errno = EIO;
        return -1;
    }
    if (dr_inside_shadow(shadow_abs) != 0)
        return -1; /* containment: never mutate outside the shadow root */
    if (S_ISDIR(st.st_mode)) {
        if (real_mkdir(shadow_abs, 0700) != 0 && errno != EEXIST)
            return -1;
        real_chmod(shadow_abs, st.st_mode & 07777);
        d = opendir(real_abs);
        if (!d)
            return -1;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            if (snprintf(r2, sizeof(r2), "%s/%s", real_abs, e->d_name)
                    >= (int)sizeof(r2)
                || snprintf(s2, sizeof(s2), "%s/%s", shadow_abs, e->d_name)
                    >= (int)sizeof(s2)) {
                closedir(d);
                errno = ENAMETOOLONG;
                return -1;
            }
            if (dr_materialize(r2, s2, lim, depth + 1) != 0) {
                int saved = errno;
                closedir(d);
                errno = saved;
                return -1;
            }
        }
        closedir(d);
        return 0;
    }
    if (S_ISLNK(st.st_mode)) {
        char target[DR_BUFSZ], starget[DR_BUFSZ];
        ssize_t n = readlink(real_abs, target, sizeof(target) - 1);

        if (n < 0)
            return -1;
        target[n] = '\0';
        /* Copy the link with a contained target: the real link may aim
         * anywhere, the shadow copy must never aim outside the tree. */
        if (dr_symlink_shadow_target(target, real_abs, starget,
                                     sizeof(starget)) != 0)
            return -1;
        if (real_symlink(starget, shadow_abs) != 0 && errno != EEXIST)
            return -1;
        return 0;
    }
    if (S_ISREG(st.st_mode))
        return dr_copy_file(real_abs, shadow_abs, st.st_mode & 07777, lim);
    /* FIFOs, sockets and devices: mirror as an empty regular file. */
    {
        int fd = real_open(shadow_abs,
                           O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);

        if (fd < 0)
            return -1;
        real_close(fd);
        return 0;
    }
}

/*
 * Make sure the shadow tree has a copy of canon. Returns 0 with shadow
 * filled in. create_empty mirrors a missing real file as an empty shadow
 * file (used by chmod, per the trace-engine contract).
 */
static int dr_materialize_into(const char *canon, char *shadow, size_t shadowsz,
                               int create_empty)
{
    dr_limits lim = {0, 0};

    if (dr_shadow_path(canon, shadow, shadowsz) != 0)
        return -1;
    if (dr_exists(shadow))
        return 0;
    if (dr_exists(canon)) {
        if (dr_ensure_parents(shadow) != 0)
            return -1;
        return dr_materialize(canon, shadow, &lim, 0);
    }
    if (!create_empty) {
        errno = ENOENT;
        return -1;
    }
    if (dr_ensure_parents(shadow) != 0)
        return -1;
    if (dr_inside_shadow(shadow) != 0)
        return -1;
    {
        int fd = real_open(shadow,
                           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);

        if (fd < 0)
            return -1;
        real_close(fd);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Operation cores (dr_active is guaranteed, zones already excluded)   */
/* ------------------------------------------------------------------ */

static int dr_openat_core(int dirfd, const char *path, int flags, mode_t mode)
{
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ], fbuf[32];
    struct stat st;
    dr_limits lim = {0, 0};
    int fd, write;

#ifdef O_TMPFILE
    /* O_TMPFILE is __O_TMPFILE | O_DIRECTORY: only treat it as an
     * anonymous inode when BOTH bits are present. A plain O_DIRECTORY
     * open must flow through the normal (shadow-aware) read path. */
    if ((flags & (int)O_TMPFILE) == (int)O_TMPFILE)
        return real_openat(dirfd, path, flags, mode); /* anonymous inode */
#endif
    write = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0;
    if (!write) {
        char rbase[DR_BUFSZ];
        const char *rd = dr_read_base(path, rbase, sizeof(rbase));

        if (rd == NULL)
            return -1; /* unresolvable base: fail closed, not misrouted */
        fd = real_openat(dirfd, rd, flags, mode);
        if (fd < 0 && errno == ENOENT) {
            /* The entry may exist only in the shadow tree (created or
             * materialized by this run): serve the read from the shadow
             * copy so directory walks and verify loops of tools such as
             * "mkdir -p" observe the simulated state. */
            int sfd = dr_open_shadow_read(dirfd, path, flags, mode);

            if (sfd >= 0)
                fd = sfd;
        }
        if (fd >= 0 && dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) == 0) {
            dr_canon(abs_, 1, canon, sizeof(canon));
            pthread_mutex_lock(&dr_lock);
            dr_fd_set(fd, canon, 0);
            pthread_mutex_unlock(&dr_lock);
        }
        return fd;
    }
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO; /* cwd unknown or path too long: fail closed */
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon)) {
        /* Exact char-device whitelist: the real open of this very path
         * string can only reach the device, never a regular file. */
        fd = real_openat(dirfd, path, flags, mode);
        if (fd >= 0) {
            pthread_mutex_lock(&dr_lock);
            dr_fd_set(fd, canon, 0); /* widen fd tracking for fchmod */
            dr_log2("NOTE_DEV_WRITE",
                    dr_is_passthrough(abs_) ? abs_ : canon, NULL);
            pthread_mutex_unlock(&dr_lock);
        }
        return fd;
    }
    /* O_NOFOLLOW on a symlink must fail ELOOP; passthrough is safe here
     * because the real open cannot succeed (and therefore cannot write). */
    if ((flags & O_NOFOLLOW) && real_lstat(abs_, &st) == 0
        && S_ISLNK(st.st_mode))
        return real_openat(dirfd, path, flags, mode);

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (dr_ensure_parents(shadow) != 0)
        goto eio;
    if (!dr_exists(shadow) && real_lstat(canon, &st) == 0) {
        if (dr_materialize(canon, shadow, &lim, 0) != 0)
            goto eio;
    }
    /* Never let the kernel follow a symlink at (or below) the shadow
     * path: fail closed instead of writing through it. */
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    fd = real_openat(AT_FDCWD, shadow, flags | O_NOFOLLOW, mode);
    if (fd >= 0) {
        snprintf(fbuf, sizeof(fbuf), "%d", flags);
        dr_fd_set(fd, canon, 1);
        dr_log2("W_OPEN", canon, fbuf);
        if (dr_is_pseudo_write(canon))
            dr_log2("NOTE_PSEUDO_WRITE", canon, NULL);
    }
    pthread_mutex_unlock(&dr_lock);
    return fd;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_unlink_core(const char *canon, int isdir)
{
    char shadow[DR_BUFSZ], tomb[DR_BUFSZ + 32];
    int have_s, have_r, fd, rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    have_s = dr_exists(shadow);
    have_r = dr_exists(canon);
    if (!have_s && !have_r) {
        pthread_mutex_unlock(&dr_lock);
        errno = ENOENT; /* faithful failure, nothing to remove */
        return -1;
    }
    if (have_s && !have_r) {
        /* Shadow-only entry (created during this run): dropping it nets
         * zero, so no tombstone and no log entry. */
        if (dr_inside_shadow(shadow) != 0)
            goto eio;
        rc = isdir ? real_rmdir(shadow) : real_unlink(shadow);
        pthread_mutex_unlock(&dr_lock);
        return rc;
    }
    if (isdir) {
        /* Faithful ENOTDIR / ENOTEMPTY for rmdir(1). */
        if (!dr_isdir(canon) || (have_s && !dr_isdir(shadow))) {
            pthread_mutex_unlock(&dr_lock);
            errno = ENOTDIR;
            return -1;
        }
        if (dr_simulated_nonempty(canon, shadow)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ENOTEMPTY;
            return -1;
        }
    }
    if (have_s) {
        if (dr_inside_shadow(shadow) != 0)
            goto eio;
        if (isdir) {
            if (real_rmdir(shadow) != 0)
                goto eio; /* fail closed: never fake a deletion */
        } else {
            if (real_unlink(shadow) != 0)
                goto eio; /* fail closed: never fake a deletion */
        }
    }
    if (dr_shadow_path(canon, tomb, sizeof(tomb) - 24) != 0)
        goto eio;
    strcat(tomb, ".dryrun-tombstone");
    if (dr_ensure_parents(tomb) != 0)
        goto eio;
    if (dr_inside_shadow(tomb) != 0)
        goto eio;
    real_unlink(tomb); /* stale tombstone from an earlier operation */
    fd = real_open(tomb, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0)
        goto eio; /* the tombstone is the deletion record: refuse to fake it */
    real_close(fd);
    dr_log2(isdir ? "W_RMDIR" : "W_UNLINK", canon, NULL);
    pthread_mutex_unlock(&dr_lock);
    return 0;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_rename_core(const char *canon_o, const char *canon_n,
                          unsigned int r2flags)
{
    char so[DR_BUFSZ], sn[DR_BUFSZ];
    dr_limits lim = {0, 0};
    int have_o, rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon_o, so, sizeof(so)) != 0
        || dr_shadow_path(canon_n, sn, sizeof(sn)) != 0)
        goto eio;
    have_o = dr_exists(so);
    if (!have_o && !dr_exists(canon_o)) {
        /* Spec: log the attempt, then faithfully fail with ENOENT. */
        dr_log2("W_RENAME", canon_o, canon_n);
        pthread_mutex_unlock(&dr_lock);
        errno = ENOENT;
        return -1;
    }
    if ((r2flags & RENAME_NOREPLACE) && !dr_exists(sn) && dr_exists(canon_n)) {
        pthread_mutex_unlock(&dr_lock);
        errno = EEXIST;
        return -1;
    }
    if ((r2flags & RENAME_EXCHANGE) && !real_renameat2) {
        pthread_mutex_unlock(&dr_lock);
        errno = EINVAL; /* cannot emulate an exchange without renameat2 */
        return -1;
    }
    if (!have_o) {
        if (dr_ensure_parents(so) != 0)
            goto eio;
        if (dr_materialize(canon_o, so, &lim, 0) != 0)
            goto eio;
    }
    if ((r2flags & RENAME_EXCHANGE) && !dr_exists(sn) && dr_exists(canon_n)) {
        if (dr_materialize(canon_n, sn, &lim, 0) != 0)
            goto eio;
    }
    if (dr_ensure_parents(sn) != 0)
        goto eio;
    if (dr_inside_shadow(so) != 0 || dr_inside_shadow(sn) != 0)
        goto eio; /* containment: both endpoints must stay in the tree */
    if (r2flags && real_renameat2)
        rc = real_renameat2(AT_FDCWD, so, AT_FDCWD, sn, r2flags);
    else
        rc = real_rename(so, sn);
    if (rc == 0)
        dr_log2("W_RENAME", canon_o, canon_n);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_mkdir_core(const char *canon, mode_t mode)
{
    char shadow[DR_BUFSZ];
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (dr_ensure_parents(shadow) != 0)
        goto eio;
    if (!dr_exists(shadow) && dr_exists(canon)) {
        pthread_mutex_unlock(&dr_lock);
        errno = EEXIST; /* the real path is taken: fail faithfully */
        return -1;
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_mkdir(shadow, mode);
    if (rc == 0)
        dr_log2("W_MKDIR", canon, NULL);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_chmod_core(const char *canon, mode_t mode)
{
    char shadow[DR_BUFSZ], mbuf[16];
    struct stat st;
    int rc;

    pthread_mutex_lock(&dr_lock);
    /* create_empty=1 per the trace-engine contract: chmod on a path that
     * does not exist yet still materializes an empty shadow file. */
    if (dr_materialize_into(canon, shadow, sizeof(shadow), 1) != 0)
        goto eio;
    if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
        pthread_mutex_unlock(&dr_lock);
        errno = ELOOP; /* fail closed: never follow a shadow symlink */
        return -1;
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_chmod(shadow, mode);
    if (rc == 0) {
        snprintf(mbuf, sizeof(mbuf), "%o", (unsigned)mode);
        dr_log2("W_CHMOD", canon, mbuf);
    }
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_truncate_core(const char *canon, off_t len)
{
    char shadow[DR_BUFSZ];
    struct stat st;
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (!dr_exists(shadow)) {
        dr_limits lim = {0, 0};
        if (dr_exists(canon)) {
            if (dr_ensure_parents(shadow) != 0)
                goto eio;
            if (dr_materialize(canon, shadow, &lim, 0) != 0)
                goto eio;
        }
        /* else: real_truncate on the missing shadow path reports ENOENT,
         * which is exactly what the real call would do. */
    }
    if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
        pthread_mutex_unlock(&dr_lock);
        errno = ELOOP; /* fail closed: never follow a shadow symlink */
        return -1;
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_truncate(shadow, len);
    if (rc == 0)
        dr_log2("W_TRUNC", canon, NULL);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_symlink_core(const char *target, const char *canon)
{
    char shadow[DR_BUFSZ], starget[DR_BUFSZ];
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (dr_ensure_parents(shadow) != 0)
        goto eio;
    if (!dr_exists(shadow) && dr_exists(canon)) {
        pthread_mutex_unlock(&dr_lock);
        errno = EEXIST;
        return -1;
    }
    /* Store a target that can only resolve inside the shadow tree; the
     * trace log keeps the original target so the report shows the
     * command's own semantics. */
    if (dr_symlink_shadow_target(target, canon, starget, sizeof(starget)) != 0)
        goto eio;
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_symlink(starget, shadow);
    if (rc == 0)
        dr_log2("W_SYMLINK", target, canon);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_link_core(const char *canon_o, const char *canon_n)
{
    char so[DR_BUFSZ], sn[DR_BUFSZ];
    dr_limits lim = {0, 0};
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon_o, so, sizeof(so)) != 0
        || dr_shadow_path(canon_n, sn, sizeof(sn)) != 0)
        goto eio;
    if (!dr_exists(so)) {
        if (!dr_exists(canon_o)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ENOENT;
            return -1;
        }
        if (dr_ensure_parents(so) != 0)
            goto eio;
        if (dr_materialize(canon_o, so, &lim, 0) != 0)
            goto eio;
    }
    if (dr_ensure_parents(sn) != 0)
        goto eio;
    if (!dr_exists(sn) && dr_exists(canon_n)) {
        pthread_mutex_unlock(&dr_lock);
        errno = EEXIST;
        return -1;
    }
    if (dr_inside_shadow(so) != 0 || dr_inside_shadow(sn) != 0)
        goto eio; /* containment: both endpoints must stay in the tree */
    rc = real_link(so, sn);
    if (rc == 0)
        dr_log2("W_LINK", canon_o, canon_n);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_mknod_core(const char *canon, mode_t mode, dev_t dev)
{
    char shadow[DR_BUFSZ];
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (dr_ensure_parents(shadow) != 0)
        goto eio;
    if (!dr_exists(shadow) && dr_exists(canon)) {
        pthread_mutex_unlock(&dr_lock);
        errno = EEXIST;
        return -1;
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_mknod(shadow, mode, dev);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

/* Metadata-only virtualization (no preview record, no log). */
static int dr_utimens_core(const char *canon, const struct timespec ts[2],
                           int flags)
{
    char shadow[DR_BUFSZ];
    dr_limits lim = {0, 0};
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (!dr_exists(shadow) && dr_exists(canon)) {
        if (dr_ensure_parents(shadow) != 0)
            goto eio;
        if (dr_materialize(canon, shadow, &lim, 0) != 0)
            goto eio;
    }
    {
        struct stat st;

        /* utimensat without AT_SYMLINK_NOFOLLOW follows symlinks: never
         * let it follow one inside the shadow tree. */
        if (!(flags & AT_SYMLINK_NOFOLLOW) && real_lstat(shadow, &st) == 0
            && S_ISLNK(st.st_mode)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ELOOP; /* fail closed: never follow a shadow symlink */
            return -1;
        }
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    rc = real_utimensat(AT_FDCWD, shadow, ts, flags);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

static int dr_chown_core(const char *canon, uid_t uid, gid_t gid, int follow)
{
    char shadow[DR_BUFSZ];
    struct stat st;
    int rc;

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0)
        goto eio;
    if (!dr_exists(shadow) && dr_exists(canon)) {
        dr_limits lim = {0, 0};
        if (dr_ensure_parents(shadow) != 0)
            goto eio;
        if (dr_materialize(canon, shadow, &lim, 0) != 0)
            goto eio;
    }
    if (!dr_exists(shadow)) {
        /* real chown would fail ENOENT; mirror that on the shadow path */
        pthread_mutex_unlock(&dr_lock);
        errno = ENOENT;
        return -1;
    }
    if (real_lstat(shadow, &st) != 0)
        goto eio;
    if (S_ISLNK(st.st_mode) && follow) {
        pthread_mutex_unlock(&dr_lock);
        errno = ELOOP; /* fail closed: never follow a shadow symlink */
        return -1;
    }
    if (dr_inside_shadow(shadow) != 0)
        goto eio;
    if (S_ISLNK(st.st_mode))
        rc = real_lchown(shadow, uid, gid);
    else
        rc = real_chown(shadow, uid, gid);
    pthread_mutex_unlock(&dr_lock);
    return rc;
eio:
    pthread_mutex_unlock(&dr_lock);
    errno = EIO;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Wrapper plumbing                                                    */
/* ------------------------------------------------------------------ */

/* Extract the optional third argument of variadic open-style calls. */
static mode_t dr_open_mode(int flags, va_list ap)
{
    if (flags & O_CREAT)
        return (mode_t)va_arg(ap, int);
    return 0;
}

static int dr_abspath(const char *path, char *out, size_t outsz)
{
    return dr_abspath_at(AT_FDCWD, path, out, outsz);
}

/* ------------------------------------------------------------------ */
/* Public interceptors                                                 */
/* ------------------------------------------------------------------ */

int open(const char *path, int flags, ...)
{
    dr_ensure_init();
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = dr_open_mode(flags, ap);
    va_end(ap);
    if (!dr_active) {
        if (!real_open) {
            errno = ENOSYS;
            return -1;
        }
        return real_open(path, flags, mode);
    }
    return dr_openat_core(AT_FDCWD, path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    dr_ensure_init();
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = dr_open_mode(flags, ap);
    va_end(ap);
    if (!dr_active) {
        if (!real_open) {
            errno = ENOSYS;
            return -1;
        }
        return real_open(path, flags, mode);
    }
    return dr_openat_core(AT_FDCWD, path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    dr_ensure_init();
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = dr_open_mode(flags, ap);
    va_end(ap);
    if (!dr_active) {
        if (!real_openat) {
            errno = ENOSYS;
            return -1;
        }
        return real_openat(dirfd, path, flags, mode);
    }
    return dr_openat_core(dirfd, path, flags, mode);
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    dr_ensure_init();
    va_list ap;
    mode_t mode;

    va_start(ap, flags);
    mode = dr_open_mode(flags, ap);
    va_end(ap);
    if (!dr_active) {
        if (!real_openat) {
            errno = ENOSYS;
            return -1;
        }
        return real_openat(dirfd, path, flags, mode);
    }
    return dr_openat_core(dirfd, path, flags, mode);
}

int creat(const char *path, mode_t mode)
{
    dr_ensure_init();
    /* intentional self-call: routes through our own open() */
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

int creat64(const char *path, mode_t mode)
{
    dr_ensure_init();
    /* intentional self-call: routes through our own open() */
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

FILE *fopen(const char *path, const char *mode)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];
    FILE *f;
    int write;

    if (!dr_active || !path || !mode)
        return real_fopen(path, mode);
    write = mode[strcspn(mode, "wa+")] != '\0';
    if (!write) {
        char rbase[DR_BUFSZ];
        const char *rd = dr_read_base(path, rbase, sizeof(rbase));

        if (rd == NULL)
            return NULL; /* unresolvable base: fail closed, not misrouted */
        f = real_fopen(rd, mode);
        if (f == NULL && errno == ENOENT) {
            /* Shadow-only entry: serve the read from the shadow copy. */
            if (dr_abspath(path, abs_, sizeof(abs_)) == 0) {
                dr_canon(abs_, 1, canon, sizeof(canon));
                pthread_mutex_lock(&dr_lock);
                if (dr_shadow_path(canon, shadow, sizeof(shadow)) == 0
                    && dr_exists(shadow)) {
                    struct stat st;

                    /* Never serve a read through a shadow symlink. */
                    if (real_lstat(shadow, &st) == 0 && !S_ISLNK(st.st_mode)) {
                        f = real_fopen(shadow, mode);
                        if (f && real_fileno) {
                            int sfd = real_fileno(f);

                            if (sfd >= 0)
                                dr_fd_set(sfd, canon, 0);
                        }
                    }
                }
                pthread_mutex_unlock(&dr_lock);
            }
        } else if (f != NULL && dr_abspath(path, abs_, sizeof(abs_)) == 0) {
            /* Track read-only fds so fchmod/ftruncate/fchown/futimens on
             * them are virtualized instead of failing closed. */
            dr_canon(abs_, 1, canon, sizeof(canon));
            pthread_mutex_lock(&dr_lock);
            if (real_fileno) {
                int rfd = real_fileno(f);

                if (rfd >= 0)
                    dr_fd_set(rfd, canon, 0);
            }
            pthread_mutex_unlock(&dr_lock);
        }
        return f;
    }
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return NULL;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon)) {
        /* Exact char-device whitelist (see dr_openat_core). */
        f = real_fopen(path, mode);
        if (f) {
            pthread_mutex_lock(&dr_lock);
            if (real_fileno) {
                int pfd = real_fileno(f);

                if (pfd >= 0)
                    dr_fd_set(pfd, canon, 0);
            }
            dr_log2("NOTE_DEV_WRITE",
                    dr_is_passthrough(abs_) ? abs_ : canon, NULL);
            pthread_mutex_unlock(&dr_lock);
        }
        return f;
    }
    if (strchr(mode, 'x') && dr_exists(canon)) {
        errno = EEXIST; /* "x" refuses to clobber the real file */
        return NULL;
    }
    pthread_mutex_lock(&dr_lock);
    if (dr_materialize_into(canon, shadow, sizeof(shadow), 0) != 0) {
        if (errno == ENOENT) {
            /* New file: only the shadow parents need to exist. */
            if (dr_shadow_path(canon, shadow, sizeof(shadow)) != 0
                || dr_ensure_parents(shadow) != 0) {
                pthread_mutex_unlock(&dr_lock);
                errno = EIO;
                return NULL;
            }
        } else {
            pthread_mutex_unlock(&dr_lock);
            errno = EIO;
            return NULL;
        }
    }
    {
        struct stat st;

        /* fopen has no O_NOFOLLOW: refuse shadow symlinks here instead. */
        if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ELOOP; /* fail closed: never follow a shadow symlink */
            return NULL;
        }
    }
    if (dr_inside_shadow(shadow) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO;
        return NULL;
    }
    pthread_mutex_unlock(&dr_lock);
    f = real_fopen(shadow, mode);
    if (f) {
        pthread_mutex_lock(&dr_lock);
        if (real_fileno) {
            int fd = real_fileno(f);
            if (fd >= 0)
                dr_fd_set(fd, canon, 1);
        }
        dr_log2("W_OPEN", canon, mode);
        if (dr_is_pseudo_write(canon))
            dr_log2("NOTE_PSEUDO_WRITE", canon, NULL);
        pthread_mutex_unlock(&dr_lock);
    }
    return f;
}

FILE *fopen64(const char *path, const char *mode)
{
    dr_ensure_init();
    return fopen(path, mode);
}

FILE *fdopen(int fd, const char *mode)
{
    dr_ensure_init();
    /* The fd number does not change, so the fd-table entry stays valid. */
    return real_fdopen(fd, mode);
}

int close(int fd)
{
    dr_ensure_init();
    int rc;

    if (!dr_active) {
        if (!real_close) {
            errno = ENOSYS;
            return -1;
        }
        return real_close(fd);
    }
    rc = real_close(fd);
    if (rc == 0) {
        pthread_mutex_lock(&dr_lock);
        dr_fd_clear(fd);
        pthread_mutex_unlock(&dr_lock);
    }
    return rc;
}

int fclose(FILE *stream)
{
    dr_ensure_init();
    int fd = -1;
    int rc;

    if (!dr_active || !real_fclose)
        return real_fclose(stream);
    if (real_fileno)
        fd = real_fileno(stream);
    rc = real_fclose(stream);
    if (rc == 0 && fd >= 0) {
        pthread_mutex_lock(&dr_lock);
        dr_fd_clear(fd);
        pthread_mutex_unlock(&dr_lock);
    }
    return rc;
}

int unlink(const char *path)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_unlink(path);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_unlink(path);
    return dr_unlink_core(canon, 0);
}

int unlinkat(int dirfd, const char *path, int flags)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];
    int isdir = (flags & AT_REMOVEDIR) != 0;

    if (!dr_active)
        return real_unlinkat(dirfd, path, flags);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_unlinkat(dirfd, path, flags);
    return dr_unlink_core(canon, isdir);
}

int rmdir(const char *path)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_rmdir(path);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_rmdir(path);
    return dr_unlink_core(canon, 1);
}

int rename(const char *oldpath, const char *newpath)
{
    dr_ensure_init();
    char ao[DR_BUFSZ], an[DR_BUFSZ], co[DR_BUFSZ], cn[DR_BUFSZ];

    if (!dr_active)
        return real_rename(oldpath, newpath);
    if (dr_abspath(oldpath, ao, sizeof(ao)) != 0
        || dr_abspath(newpath, an, sizeof(an)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(ao, 0, co, sizeof(co));
    dr_canon(an, 0, cn, sizeof(cn));
    /* Multi-path passthrough only when BOTH sides are whitelisted
     * devices; otherwise both endpoints are virtualized in the shadow
     * tree (materializing whichever side needs it). */
    if ((dr_is_passthrough(ao) || dr_is_passthrough(co))
        && (dr_is_passthrough(an) || dr_is_passthrough(cn)))
        return real_rename(oldpath, newpath);
    return dr_rename_core(co, cn, 0);
}

int renameat(int olddirfd, const char *oldpath, int newdirfd,
             const char *newpath)
{
    dr_ensure_init();
    char ao[DR_BUFSZ], an[DR_BUFSZ], co[DR_BUFSZ], cn[DR_BUFSZ];

    if (!dr_active)
        return real_renameat(olddirfd, oldpath, newdirfd, newpath);
    if (dr_abspath_at(olddirfd, oldpath, ao, sizeof(ao)) != 0
        || dr_abspath_at(newdirfd, newpath, an, sizeof(an)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(ao, 0, co, sizeof(co));
    dr_canon(an, 0, cn, sizeof(cn));
    /* Both sides must be whitelisted devices to pass through (rename). */
    if ((dr_is_passthrough(ao) || dr_is_passthrough(co))
        && (dr_is_passthrough(an) || dr_is_passthrough(cn)))
        return real_renameat(olddirfd, oldpath, newdirfd, newpath);
    return dr_rename_core(co, cn, 0);
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
              const char *newpath, unsigned int flags)
{
    dr_ensure_init();
    char ao[DR_BUFSZ], an[DR_BUFSZ], co[DR_BUFSZ], cn[DR_BUFSZ];

    if (!dr_active) {
        if (!real_renameat2)
            return renameat(olddirfd, oldpath, newdirfd, newpath);
        return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    if (dr_abspath_at(olddirfd, oldpath, ao, sizeof(ao)) != 0
        || dr_abspath_at(newdirfd, newpath, an, sizeof(an)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(ao, 0, co, sizeof(co));
    dr_canon(an, 0, cn, sizeof(cn));
    /* Both sides must be whitelisted devices to pass through (renameat2). */
    if ((dr_is_passthrough(ao) || dr_is_passthrough(co))
        && (dr_is_passthrough(an) || dr_is_passthrough(cn))) {
        if (!real_renameat2)
            return real_renameat(olddirfd, oldpath, newdirfd, newpath);
        return real_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    if (!real_renameat2 && (flags & RENAME_EXCHANGE)) {
        errno = EINVAL;
        return -1;
    }
    return dr_rename_core(co, cn, flags);
}

int mkdir(const char *path, mode_t mode)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_mkdir(path, mode);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_mkdir(path, mode);
    return dr_mkdir_core(canon, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_mkdirat(dirfd, path, mode);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_mkdirat(dirfd, path, mode);
    return dr_mkdir_core(canon, mode);
}

int chmod(const char *path, mode_t mode)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_chmod(path, mode);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_chmod(path, mode);
    return dr_chmod_core(canon, mode);
}

int fchmod(int fd, mode_t mode)
{
    dr_ensure_init();
    char shadow[DR_BUFSZ], path[DR_BUFSZ], mbuf[16];
    int shadowed, rc;

    if (!dr_active)
        return real_fchmod(fd, mode);
    pthread_mutex_lock(&dr_lock);
    if (dr_fd_get(fd, path, sizeof(path), &shadowed) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO; /* untracked fd: fail closed, never touch the file */
        return -1;
    }
    snprintf(mbuf, sizeof(mbuf), "%o", (unsigned)mode);
    if (shadowed) {
        dr_log2("W_CHMOD", path, mbuf);
        pthread_mutex_unlock(&dr_lock);
        return real_fchmod(fd, mode); /* fd is already the shadow copy */
    }
    if (dr_materialize_into(path, shadow, sizeof(shadow), 1) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO;
        return -1;
    }
    {
        struct stat st;

        if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ELOOP; /* fail closed: never follow a shadow symlink */
            return -1;
        }
        if (dr_inside_shadow(shadow) != 0) {
            pthread_mutex_unlock(&dr_lock);
            errno = EIO;
            return -1;
        }
    }
    rc = real_chmod(shadow, mode);
    if (rc == 0)
        dr_log2("W_CHMOD", path, mbuf);
    pthread_mutex_unlock(&dr_lock);
    return rc;
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_fchmodat(dirfd, path, mode, flags);
    if (flags & AT_EMPTY_PATH)
        return fchmod(dirfd, mode);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_fchmodat(dirfd, path, mode, flags);
    return dr_chmod_core(canon, mode);
}

int fchmodat2(int dirfd, const char *path, mode_t mode, int flags)
{
    dr_ensure_init();
    /* The shadow semantics are the same; reuse the fchmodat logic. */
    return fchmodat(dirfd, path, mode, flags);
}

int truncate(const char *path, off_t length)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_truncate(path, length);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_truncate(path, length);
    return dr_truncate_core(canon, length);
}

int truncate64(const char *path, off_t length)
{
    dr_ensure_init();
    return truncate(path, length);
}

int ftruncate(int fd, off_t length)
{
    dr_ensure_init();
    char path[DR_BUFSZ];
    int shadowed;

    if (!dr_active)
        return real_ftruncate(fd, length);
    pthread_mutex_lock(&dr_lock);
    if (dr_fd_get(fd, path, sizeof(path), &shadowed) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO; /* untracked fd: fail closed, never touch the file */
        return -1;
    }
    if (shadowed) {
        dr_log2("W_TRUNC", path, NULL);
        pthread_mutex_unlock(&dr_lock);
        return real_ftruncate(fd, length); /* already the shadow copy */
    }
    pthread_mutex_unlock(&dr_lock);
    /* Tracked non-shadowed fds are read-only: the real call fails EINVAL
     * exactly like it would against the real file. */
    return real_ftruncate(fd, length);
}

int ftruncate64(int fd, off_t length)
{
    dr_ensure_init();
    return ftruncate(fd, length);
}

int symlink(const char *target, const char *linkpath)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_symlink(target, linkpath);
    if (dr_abspath(linkpath, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_symlink(target, linkpath);
    return dr_symlink_core(target, canon);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    dr_ensure_init();
    if (!real_symlinkat) {
        errno = ENOSYS;
        return -1;
    }
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_symlinkat(target, newdirfd, linkpath);
    if (dr_abspath_at(newdirfd, linkpath, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_symlinkat(target, newdirfd, linkpath);
    return dr_symlink_core(target, canon);
}

int link(const char *oldpath, const char *newpath)
{
    dr_ensure_init();
    char ao[DR_BUFSZ], an[DR_BUFSZ], co[DR_BUFSZ], cn[DR_BUFSZ];

    if (!dr_active)
        return real_link(oldpath, newpath);
    if (dr_abspath(oldpath, ao, sizeof(ao)) != 0
        || dr_abspath(newpath, an, sizeof(an)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(ao, 0, co, sizeof(co));
    dr_canon(an, 0, cn, sizeof(cn));
    /* Both sides must be whitelisted devices to pass through (link). */
    if ((dr_is_passthrough(ao) || dr_is_passthrough(co))
        && (dr_is_passthrough(an) || dr_is_passthrough(cn)))
        return real_link(oldpath, newpath);
    return dr_link_core(co, cn);
}

int linkat(int olddirfd, const char *oldpath, int newdirfd,
           const char *newpath, int flags)
{
    dr_ensure_init();
    if (!real_linkat) {
        errno = ENOSYS;
        return -1;
    }
    char ao[DR_BUFSZ], an[DR_BUFSZ], co[DR_BUFSZ], cn[DR_BUFSZ];

    if (!dr_active)
        return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    if (dr_abspath_at(olddirfd, oldpath, ao, sizeof(ao)) != 0
        || dr_abspath_at(newdirfd, newpath, an, sizeof(an)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(ao, 0, co, sizeof(co));
    dr_canon(an, 0, cn, sizeof(cn));
    /* Both sides must be whitelisted devices to pass through (linkat). */
    if ((dr_is_passthrough(ao) || dr_is_passthrough(co))
        && (dr_is_passthrough(an) || dr_is_passthrough(cn)))
        return real_linkat(olddirfd, oldpath, newdirfd, newpath, flags);
    return dr_link_core(co, cn);
}

int mknod(const char *path, mode_t mode, dev_t dev)
{
    dr_ensure_init();
    if (!real_mknod) {
        errno = ENOSYS;
        return -1;
    }
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_mknod(path, mode, dev);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_mknod(path, mode, dev);
    return dr_mknod_core(canon, mode, dev);
}

int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
    dr_ensure_init();
    if (!real_mknodat) {
        errno = ENOSYS;
        return -1;
    }
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_mknodat(dirfd, path, mode, dev);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_mknodat(dirfd, path, mode, dev);
    return dr_mknod_core(canon, mode, dev);
}

/*
 * mkstemp family: glibc creates the file with an internal (non-PLT)
 * open, so without this interception a plain "sed -i" would leave its
 * temporary file in the real working directory. We run the real
 * mkstemp on the shadow template instead, then copy the generated
 * suffix back into the caller's buffer so the program keeps seeing the
 * name it expects.
 */
static int dr_mkstemp_core(char *tmpl, int suffixlen, int flags)
{
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], stempl[DR_BUFSZ], fbuf[32];
    size_t tlen, tail;
    int fd;

    tlen = strlen(tmpl);
    if (suffixlen < 0 || tlen < (size_t)suffixlen + 6)
        goto einval;
    tail = (size_t)suffixlen + 6;
    if (strncmp(tmpl + tlen - tail, "XXXXXX", 6) != 0)
        goto einval;
    if (dr_abspath(tmpl, abs_, sizeof(abs_)) != 0) {
        errno = EIO; /* cwd unknown: fail closed rather than go real */
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon)) {
        /* pseudo filesystems: let glibc create the (harmless) entry */
        if (suffixlen == 0 && flags == 0 && real_mkstemp)
            return real_mkstemp(tmpl);
        if (suffixlen == 0 && real_mkostemp)
            return real_mkostemp(tmpl, flags);
        if (suffixlen > 0 && flags == 0 && real_mkstemps)
            return real_mkstemps(tmpl, suffixlen);
        if (suffixlen > 0 && real_mkostemps)
            return real_mkostemps(tmpl, suffixlen, flags);
        errno = ENOSYS;
        return -1;
    }
    if (dr_shadow_path(canon, stempl, sizeof(stempl)) != 0) {
        errno = EIO;
        return -1;
    }
    pthread_mutex_lock(&dr_lock);
    if (dr_ensure_parents(stempl) != 0 || dr_inside_shadow(stempl) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO;
        return -1;
    }
    if (suffixlen == 0 && (flags == 0 || !real_mkostemp)) {
        if (!real_mkstemp)
            goto nosys;
        fd = real_mkstemp(stempl);
    } else if (suffixlen == 0) {
        fd = real_mkostemp(stempl, flags);
    } else if (flags == 0 || !real_mkostemps) {
        if (!real_mkstemps)
            goto nosys;
        fd = real_mkstemps(stempl, suffixlen);
    } else {
        fd = real_mkostemps(stempl, suffixlen, flags);
    }
    if (fd < 0) {
        pthread_mutex_unlock(&dr_lock);
        return -1;
    }
    /* Mirror the generated suffix back into the caller's template. */
    memcpy(tmpl + tlen - tail, stempl + strlen(stempl) - tail, tail);
    /* Track the fd under the real path with the final suffix in place. */
    memcpy(canon + strlen(canon) - tail, stempl + strlen(stempl) - tail, tail);
    dr_fd_set(fd, canon, 1);
    snprintf(fbuf, sizeof(fbuf), "%d", O_RDWR | O_CREAT | O_EXCL);
    dr_log2("W_OPEN", canon, fbuf);
    pthread_mutex_unlock(&dr_lock);
    return fd;
nosys:
    pthread_mutex_unlock(&dr_lock);
    errno = ENOSYS;
    return -1;
einval:
    errno = EINVAL;
    return -1;
}

int mkstemp(char *tmpl)
{
    dr_ensure_init();
    if (!dr_active)
        return real_mkstemp ? real_mkstemp(tmpl) : (errno = ENOSYS, -1);
    return dr_mkstemp_core(tmpl, 0, 0);
}

int mkstemp64(char *tmpl)
{
    return mkstemp(tmpl);
}

int mkostemp(char *tmpl, int flags)
{
    dr_ensure_init();
    if (!dr_active)
        return real_mkostemp ? real_mkostemp(tmpl, flags)
                             : (errno = ENOSYS, -1);
    return dr_mkstemp_core(tmpl, 0, flags);
}

int mkostemp64(char *tmpl, int flags)
{
    return mkostemp(tmpl, flags);
}

int mkstemps(char *tmpl, int suffixlen)
{
    dr_ensure_init();
    if (!dr_active)
        return real_mkstemps ? real_mkstemps(tmpl, suffixlen)
                             : (errno = ENOSYS, -1);
    return dr_mkstemp_core(tmpl, suffixlen, 0);
}

int mkstemps64(char *tmpl, int suffixlen)
{
    return mkstemps(tmpl, suffixlen);
}

int mkostemps(char *tmpl, int suffixlen, int flags)
{
    dr_ensure_init();
    if (!dr_active)
        return real_mkostemps ? real_mkostemps(tmpl, suffixlen, flags)
                              : (errno = ENOSYS, -1);
    return dr_mkstemp_core(tmpl, suffixlen, flags);
}

int mkostemps64(char *tmpl, int suffixlen, int flags)
{
    return mkostemps(tmpl, suffixlen, flags);
}

char *mkdtemp(char *tmpl)
{
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], stempl[DR_BUFSZ];
    size_t tlen;
    char *rc;

    dr_ensure_init();
    if (!dr_active)
        return real_mkdtemp ? real_mkdtemp(tmpl) : (errno = ENOSYS, NULL);
    tlen = strlen(tmpl);
    if (tlen < 6 || strncmp(tmpl + tlen - 6, "XXXXXX", 6) != 0) {
        errno = EINVAL;
        return NULL;
    }
    if (dr_abspath(tmpl, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return NULL;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_mkdtemp(tmpl);
    if (dr_shadow_path(canon, stempl, sizeof(stempl)) != 0) {
        errno = EIO;
        return NULL;
    }
    pthread_mutex_lock(&dr_lock);
    if (dr_ensure_parents(stempl) != 0 || dr_inside_shadow(stempl) != 0
        || real_mkdtemp(stempl) == NULL) {
        pthread_mutex_unlock(&dr_lock);
        return NULL;
    }
    memcpy(tmpl + tlen - 6, stempl + strlen(stempl) - 6, 6);
    memcpy(canon + strlen(canon) - 6, stempl + strlen(stempl) - 6, 6);
    dr_log2("W_MKDIR", canon, NULL);
    pthread_mutex_unlock(&dr_lock);
    rc = tmpl;
    return rc;
}

int dup(int oldfd)
{
    dr_ensure_init();
    int fd;

    if (!dr_active)
        return real_dup(oldfd);
    fd = real_dup(oldfd);
    if (fd >= 0) {
        pthread_mutex_lock(&dr_lock);
        dr_fd_copy(oldfd, fd);
        pthread_mutex_unlock(&dr_lock);
    }
    return fd;
}

int dup2(int oldfd, int newfd)
{
    dr_ensure_init();
    int fd;

    if (!dr_active)
        return real_dup2(oldfd, newfd);
    if (oldfd == newfd)
        return real_dup2(oldfd, newfd);
    fd = real_dup2(oldfd, newfd);
    if (fd >= 0) {
        pthread_mutex_lock(&dr_lock);
        dr_fd_clear(newfd);
        dr_fd_copy(oldfd, newfd);
        pthread_mutex_unlock(&dr_lock);
    }
    return fd;
}

int dup3(int oldfd, int newfd, int flags)
{
    dr_ensure_init();
    int fd;

    if (!dr_active)
        return real_dup3 ? real_dup3(oldfd, newfd, flags)
                         : real_dup2(oldfd, newfd);
    if (oldfd == newfd) {
        errno = EINVAL;
        return -1;
    }
    fd = real_dup3 ? real_dup3(oldfd, newfd, flags) : real_dup2(oldfd, newfd);
    if (fd >= 0) {
        pthread_mutex_lock(&dr_lock);
        dr_fd_clear(newfd);
        dr_fd_copy(oldfd, newfd);
        pthread_mutex_unlock(&dr_lock);
    }
    return fd;
}

/*
 * Commit a tracked (possibly virtual) working directory. Under dr_lock.
 * Exported to children via DRYRUN_CWD so that programs exec'd after a
 * chdir still resolve relative paths against the simulated location.
 */
static void dr_cwd_commit(const char *newcwd, int virtualcwd)
{
    snprintf(dr_cwd, sizeof(dr_cwd), "%s", newcwd);
    dr_cwd_valid = 1;
    dr_cwd_virtual = virtualcwd;
    setenv("DRYRUN_CWD", dr_cwd, 1);
}

/* Try to enter canon, which exists in the shadow tree only. */
static int dr_virtual_chdir(const char *canon)
{
    char shadow[DR_BUFSZ];

    pthread_mutex_lock(&dr_lock);
    if (dr_shadow_path(canon, shadow, sizeof(shadow)) == 0 && dr_isdir(shadow)) {
        dr_cwd_commit(canon, 1);
        pthread_mutex_unlock(&dr_lock);
        return 0;
    }
    pthread_mutex_unlock(&dr_lock);
    return -1;
}

static int dr_chdir_impl(const char *path);

int chdir(const char *path)
{
    dr_ensure_init();

    if (!dr_active)
        return real_chdir(path);
    return dr_chdir_impl(path);
}

static int dr_chdir_impl(const char *path)
{
    char tmp[DR_BUFSZ], canon[DR_BUFSZ];
    int rc, saved;

    if (!path) {
        errno = EFAULT;
        return -1;
    }
    if (dr_cwd_virtual && path[0] != '/') {
        /* The real cwd is stale: resolve against the tracked one first. */
        if (dr_abspath(path, tmp, sizeof(tmp)) != 0) {
            errno = EIO;
            return -1;
        }
        path = tmp;
    }
    rc = real_chdir(path);
    if (rc != 0 && errno == ENOENT) {
        /* The directory may exist only in the shadow tree because this
         * run created it: virtualize the chdir instead of failing. */
        saved = errno;
        if ((path[0] == '/' && dr_normalize(path, tmp, sizeof(tmp)) == 0)
            || (path[0] != '/' && dr_abspath(path, tmp, sizeof(tmp)) == 0)) {
            dr_canon(tmp, 0, canon, sizeof(canon));
            if (dr_virtual_chdir(canon) == 0)
                return 0;
        }
        errno = saved;
        return rc;
    }
    if (rc != 0)
        return rc;
    /* Real chdir succeeded: track the new directory lexically. */
    if (path[0] == '/')
        rc = dr_normalize(path, tmp, sizeof(tmp));
    else
        rc = dr_abspath(path, tmp, sizeof(tmp));
    pthread_mutex_lock(&dr_lock);
    if (rc != 0) {
        dr_cwd_valid = 0; /* cannot track cwd: later writes fail closed */
    } else {
        dr_cwd_commit(tmp, 0);
    }
    pthread_mutex_unlock(&dr_lock);
    return 0;
}

int fchdir(int fd)
{
    dr_ensure_init();
    if (!real_fchdir) {
        errno = ENOSYS;
        return -1;
    }
    char link[64], target[DR_BUFSZ], path[DR_BUFSZ];
    ssize_t n;
    int rc, dummy;

    if (!dr_active)
        return real_fchdir(fd);
    rc = real_fchdir(fd);
    if (rc != 0)
        return rc;
    pthread_mutex_lock(&dr_lock);
    if (dr_fd_get(fd, path, sizeof(path), &dummy) == 0) {
        dr_cwd_commit(path, 0);
    } else {
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
        n = readlink(link, target, sizeof(target) - 1);
        if (n > 0) {
            target[n] = '\0';
            dr_cwd_commit(target, 0);
        } else {
            dr_cwd_valid = 0; /* unknown cwd: later writes fail closed */
        }
    }
    pthread_mutex_unlock(&dr_lock);
    return 0;
}

int utimensat(int dirfd, const char *path, const struct timespec times[2],
              int flags)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_utimensat(dirfd, path, times, flags);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, !(flags & AT_SYMLINK_NOFOLLOW), canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_utimensat(dirfd, path, times, flags);
    return dr_utimens_core(canon, times, flags);
}

int futimens(int fd, const struct timespec times[2])
{
    dr_ensure_init();
    if (!real_futimens) {
        errno = ENOSYS;
        return -1;
    }
    char shadow[DR_BUFSZ], path[DR_BUFSZ];
    int shadowed, rc;

    if (!dr_active)
        return real_futimens(fd, times);
    pthread_mutex_lock(&dr_lock);
    if (dr_fd_get(fd, path, sizeof(path), &shadowed) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO; /* untracked fd: fail closed, never touch the file */
        return -1;
    }
    if (shadowed) {
        pthread_mutex_unlock(&dr_lock);
        return real_futimens(fd, times); /* already the shadow copy */
    }
    rc = dr_materialize_into(path, shadow, sizeof(shadow), 0);
    if (rc != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = ENOENT; /* metadata op on a missing file: faithful miss */
        return -1;
    }
    {
        struct stat st;

        if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ELOOP; /* fail closed: never follow a shadow symlink */
            return -1;
        }
        if (dr_inside_shadow(shadow) != 0) {
            pthread_mutex_unlock(&dr_lock);
            errno = EIO;
            return -1;
        }
    }
    pthread_mutex_unlock(&dr_lock);
    return real_utimensat(AT_FDCWD, shadow, times, 0);
}

/* Convert a utimes-style timeval pair (NULL = "now") to timespec. */
static struct timespec *dr_tv_to_ts(const struct timeval times[2],
                                    struct timespec ts[2])
{
    int i;

    if (!times)
        return NULL;
    for (i = 0; i < 2; i++) {
        ts[i].tv_sec = times[i].tv_sec;
        ts[i].tv_nsec = times[i].tv_usec * 1000;
    }
    return ts;
}

int utimes(const char *path, const struct timeval times[2])
{
    dr_ensure_init();
    struct timespec ts[2], *tsp;

    tsp = dr_tv_to_ts(times, ts);
    if (!dr_active) {
        if (!real_utimensat) {
            errno = ENOSYS;
            return -1;
        }
        return real_utimensat(AT_FDCWD, path, tsp, 0);
    }
    return utimensat(AT_FDCWD, path, tsp, 0);
}

int lutimes(const char *path, const struct timeval times[2])
{
    dr_ensure_init();
    struct timespec ts[2], *tsp;

    tsp = dr_tv_to_ts(times, ts);
    if (!dr_active) {
        if (!real_utimensat) {
            errno = ENOSYS;
            return -1;
        }
        return real_utimensat(AT_FDCWD, path, tsp, AT_SYMLINK_NOFOLLOW);
    }
    return utimensat(AT_FDCWD, path, tsp, AT_SYMLINK_NOFOLLOW);
}

int chown(const char *path, uid_t owner, gid_t group)
{
    dr_ensure_init();
    if (!real_chown) {
        errno = ENOSYS;
        return -1;
    }
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_chown(path, owner, group);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_chown(path, owner, group);
    return dr_chown_core(canon, owner, group, 1);
}

int lchown(const char *path, uid_t owner, gid_t group)
{
    dr_ensure_init();
    if (!real_lchown) {
        errno = ENOSYS;
        return -1;
    }
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_lchown(path, owner, group);
    if (dr_abspath(path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_lchown(path, owner, group);
    return dr_chown_core(canon, owner, group, 0);
}

int fchown(int fd, uid_t owner, gid_t group)
{
    dr_ensure_init();
    if (!real_fchown) {
        errno = ENOSYS;
        return -1;
    }
    char shadow[DR_BUFSZ], path[DR_BUFSZ];
    int shadowed, rc;

    if (!dr_active)
        return real_fchown(fd, owner, group);
    pthread_mutex_lock(&dr_lock);
    if (dr_fd_get(fd, path, sizeof(path), &shadowed) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO; /* untracked fd: fail closed, never touch the file */
        return -1;
    }
    if (shadowed) {
        pthread_mutex_unlock(&dr_lock);
        return real_fchown(fd, owner, group); /* already shadow copy */
    }
    if (dr_materialize_into(path, shadow, sizeof(shadow), 1) != 0) {
        pthread_mutex_unlock(&dr_lock);
        errno = EIO;
        return -1;
    }
    {
        struct stat st;

        if (real_lstat(shadow, &st) == 0 && S_ISLNK(st.st_mode)) {
            pthread_mutex_unlock(&dr_lock);
            errno = ELOOP; /* fail closed: never follow a shadow symlink */
            return -1;
        }
        if (dr_inside_shadow(shadow) != 0) {
            pthread_mutex_unlock(&dr_lock);
            errno = EIO;
            return -1;
        }
    }
    rc = real_chown(shadow, owner, group);
    pthread_mutex_unlock(&dr_lock);
    return rc;
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ];

    if (!dr_active)
        return real_fchownat(dirfd, path, owner, group, flags);
    if (flags & AT_EMPTY_PATH)
        return fchown(dirfd, owner, group);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0) {
        errno = EIO;
        return -1;
    }
    dr_canon(abs_, !(flags & AT_SYMLINK_NOFOLLOW), canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_fchownat(dirfd, path, owner, group, flags);
    return dr_chown_core(canon, owner, group, !(flags & AT_SYMLINK_NOFOLLOW));
}

/* ------------------------------------------------------------------ */
/* Simulated stat/access view                                          */
/*                                                                    */
/* Tools verify their own progress with stat/lstat/fstatat/access      */
/* ("mkdir -p" stats every level it creates). These wrappers report   */
/* the simulated state: shadow copies win, tombstones hide the real   */
/* entry. They are read-only, take no locks, and fall back to plain   */
/* passthrough whenever anything is unusual.                          */
/* ------------------------------------------------------------------ */

int stat(const char *path, struct stat *st)
{
    dr_ensure_init();
    const char *arg = path; /* may be NULL despite the nonnull prototype */
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];

    if (!dr_active || !real_stat || !arg)
        return real_stat ? real_stat(arg, st) : (errno = ENOSYS, -1);
    if (arg[0] == '/') {
        if (dr_normalize(arg, abs_, sizeof(abs_)) != 0)
            return real_stat(arg, st);
    } else {
        if (!dr_cwd_valid || dr_abspath(arg, abs_, sizeof(abs_)) != 0)
            return real_stat(arg, st);
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_stat(arg, st);
    switch (dr_view(canon, shadow, sizeof(shadow))) {
    case DR_VIEW_SHADOW:
        if (real_stat(shadow, st) == 0)
            return 0;
        break;
    case DR_VIEW_GONE:
        errno = ENOENT;
        return -1;
    default:
        break;
    }
    return real_stat(abs_, st);
}

int lstat(const char *path, struct stat *st)
{
    dr_ensure_init();
    const char *arg = path; /* may be NULL despite the nonnull prototype */
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];

    if (!dr_active || !real_lstat || !arg)
        return real_lstat ? real_lstat(arg, st) : (errno = ENOSYS, -1);
    if (arg[0] == '/') {
        if (dr_normalize(arg, abs_, sizeof(abs_)) != 0)
            return real_lstat(arg, st);
    } else {
        if (!dr_cwd_valid || dr_abspath(arg, abs_, sizeof(abs_)) != 0)
            return real_lstat(arg, st);
    }
    dr_canon(abs_, 0, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_lstat(arg, st);
    switch (dr_view(canon, shadow, sizeof(shadow))) {
    case DR_VIEW_SHADOW:
        if (real_lstat(shadow, st) == 0)
            return 0;
        break;
    case DR_VIEW_GONE:
        errno = ENOENT;
        return -1;
    default:
        break;
    }
    return real_lstat(abs_, st);
}

int fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
    dr_ensure_init();
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];
    int follow;

    if (!dr_active || !real_fstatat || !path || !path[0])
        return real_fstatat
            ? real_fstatat(dirfd, path, st, flags)
            : (errno = ENOSYS, -1);
    follow = !(flags & AT_SYMLINK_NOFOLLOW);
    if (dr_abspath_at(dirfd, path, abs_, sizeof(abs_)) != 0)
        return real_fstatat(dirfd, path, st, flags);
    dr_canon(abs_, follow, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_fstatat(dirfd, path, st, flags);
    switch (dr_view(canon, shadow, sizeof(shadow))) {
    case DR_VIEW_SHADOW:
        if (real_fstatat(AT_FDCWD, shadow, st, flags) == 0)
            return 0;
        break;
    case DR_VIEW_GONE:
        errno = ENOENT;
        return -1;
    default:
        break;
    }
    return real_fstatat(AT_FDCWD, abs_, st, flags);
}

int access(const char *path, int mode)
{
    dr_ensure_init();
    const char *arg = path; /* may be NULL despite the nonnull prototype */
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];

    if (!dr_active || !real_access || !arg)
        return real_access ? real_access(arg, mode) : (errno = ENOSYS, -1);
    if (arg[0] == '/') {
        if (dr_normalize(arg, abs_, sizeof(abs_)) != 0)
            return real_access(arg, mode);
    } else {
        if (!dr_cwd_valid || dr_abspath(arg, abs_, sizeof(abs_)) != 0)
            return real_access(arg, mode);
    }
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_access(arg, mode);
    switch (dr_view(canon, shadow, sizeof(shadow))) {
    case DR_VIEW_SHADOW:
        return real_access(shadow, mode);
    case DR_VIEW_GONE:
        errno = ENOENT;
        return -1;
    default:
        return real_access(abs_, mode);
    }
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    dr_ensure_init();
    const char *arg = path; /* may be NULL despite the nonnull prototype */
    char abs_[DR_BUFSZ], canon[DR_BUFSZ], shadow[DR_BUFSZ];

    if (!dr_active || !real_faccessat || !arg || !arg[0])
        return real_faccessat
            ? real_faccessat(dirfd, arg, mode, flags)
            : (errno = ENOSYS, -1);
    if (dr_abspath_at(dirfd, arg, abs_, sizeof(abs_)) != 0)
        return real_faccessat(dirfd, arg, mode, flags);
    dr_canon(abs_, 1, canon, sizeof(canon));
    if (dr_is_passthrough(abs_) || dr_is_passthrough(canon))
        return real_faccessat(dirfd, path, mode, flags);
    switch (dr_view(canon, shadow, sizeof(shadow))) {
    case DR_VIEW_SHADOW:
        return real_faccessat(AT_FDCWD, shadow, mode, flags);
    case DR_VIEW_GONE:
        errno = ENOENT;
        return -1;
    default:
        return real_faccessat(AT_FDCWD, abs_, mode, flags);
    }
}
