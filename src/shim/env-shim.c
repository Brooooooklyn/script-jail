/*
 * script-jail — env-shim.c
 * LD_PRELOAD shim: wraps getenv/secure_getenv to audit env-var reads and
 * hide protected names. Licensed under the MIT License.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ── tunables ─────────────────────────────────────────────────────────────── */

#define MAX_PROTECTED 64    /* max names in protect-list */
#define NAME_MAX_LEN  256   /* max protect-list name length (per entry) */
#define JSONL_BUF     4096  /* must be ≤ PIPE_BUF for atomic writes */

/* ── thread-local recursion guard ────────────────────────────────────────── */
/*
 * dlsym(), fopen(), and clock_gettime() can internally call getenv() on some
 * libc implementations.  This guard prevents infinite recursion.
 *
 * IMPORTANT: in_shim is set to 1 for the *entire duration* of shim_init()
 * (including fopen/fgets/fclose for the protect-list) so that any getenv()
 * re-entrant call made by libc during init is forwarded directly to the real
 * implementation without re-entering pthread_once.
 */
static __thread int in_shim = 0;

/* ── protect-list ────────────────────────────────────────────────────────── */

static char  protected_names[MAX_PROTECTED][NAME_MAX_LEN];
static int   protected_count = 0;

static int is_protected(const char *name)
{
    if (!name) return 0;
    for (int i = 0; i < protected_count; i++) {
        if (strcmp(protected_names[i], name) == 0)
            return 1;
    }
    return 0;
}

/* ── log fd ───────────────────────────────────────────────────────────────── */

static int log_fd = -1; /* -1 means silent */

/* ── real function pointers ──────────────────────────────────────────────── */

typedef char *(*getenv_fn)(const char *);

static getenv_fn real_getenv        = NULL;
static getenv_fn real_secure_getenv = NULL;

static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;

static void resolve_syms(void)
{
    /*
     * in_shim is already 1 on the calling thread (set by shim_init or the
     * getenv wrapper before pthread_once).  dlsym may call getenv internally;
     * the bypass guard in our wrapper will forward those calls to real_getenv
     * (NULL-safe: returns NULL if not yet resolved).
     */
    real_getenv        = (getenv_fn)dlsym(RTLD_NEXT, "getenv");
    real_secure_getenv = (getenv_fn)dlsym(RTLD_NEXT, "secure_getenv");
    /* __secure_getenv is a deprecated alias; try both names */
    if (!real_secure_getenv)
        real_secure_getenv = (getenv_fn)dlsym(RTLD_NEXT, "__secure_getenv");
}

/* ── atomic write with EINTR retry ─────────────────────────────────────── */

static void write_all(int fd, const char *buf, size_t len)
{
    /*
     * write() of a buffer ≤ PIPE_BUF bytes to a pipe is atomic on Linux.
     * We retry only on EINTR; short writes and other errors are silently
     * discarded (losing an audit record is preferable to corrupting one).
     */
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break; /* EPIPE, EBADF, etc. — drop and stop */
        }
        if ((size_t)n >= len) break; /* full write (normal case) */
        /* short write on a regular file — advance and retry */
        buf += (size_t)n;
        len -= (size_t)n;
    }
}

/* ── constructor: load protect-list + log-fd ─────────────────────────────── */

/*
 * Security note (v1 limitation): SCRIPT_JAIL_PROTECTED_ENV_FILE is read from the
 * guest-visible environment.  A guest process that spawns a child with
 * LD_PRELOAD still set but SCRIPT_JAIL_PROTECTED_ENV_FILE unset or pointing at an
 * empty file will inherit no protected names.  In v1 the host is responsible
 * for making this env var read-only at the container boundary (e.g. via
 * seccomp/landlock preventing unsetenv, or passing policy through a sealed
 * memfd).
 *
 * TODO(v2): pass the protect-list through a trusted inherited fd (e.g. a
 * sealed memfd or a read-only bind-mount) so that guest code cannot bypass
 * protection by unsetting the env var before exec.
 */

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void do_init(void)
{
    /*
     * Callers (shim_init and the getenv wrapper) set in_shim = 1 before
     * invoking pthread_once, so any getenv() re-entry during init takes the
     * bypass branch and does not deadlock on init_once.  We assert this
     * invariant with a redundant set for clarity.
     */
    in_shim = 1;

    /* Resolve real function pointers. */
    pthread_once(&resolve_once, resolve_syms);

    /*
     * Resolve the log destination.  Prefer SCRIPT_JAIL_LOG_FILE (file path,
     * required in production because npm spawns lifecycle node processes
     * with `stdio: 'inherit'`, which only propagates fds 0-2 — fd 3 is
     * closed in the child).  Fall back to SCRIPT_JAIL_LOG_FD for tests
     * that wire a pipe directly.
     *
     * One open per process: each LD_PRELOAD instance gets its own fd via
     * O_APPEND so concurrent writers don't race on file offset.  POSIX
     * guarantees atomic writes for messages smaller than PIPE_BUF on
     * regular files; our JSONL lines fit comfortably in JSONL_BUF (4096).
     */
    {
        const char *path = real_getenv ? real_getenv("SCRIPT_JAIL_LOG_FILE") : NULL;
        if (path && *path) {
            int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
            if (fd >= 0) log_fd = fd;
            /* On failure (EACCES, ENOENT for a missing dir, etc.) fall through
             * to SCRIPT_JAIL_LOG_FD so tests still work. */
        }
    }
    if (log_fd < 0) {
        const char *fd_str = real_getenv ? real_getenv("SCRIPT_JAIL_LOG_FD") : NULL;
        if (fd_str && *fd_str) {
            char *end = NULL;
            long fd = strtol(fd_str, &end, 10);
            if (end && *end == '\0' && fd >= 0 && fd <= 65535)
                log_fd = (int)fd;
        }
    }

    /* Load protect-list file. */
    {
        const char *path = real_getenv ? real_getenv("SCRIPT_JAIL_PROTECTED_ENV_FILE") : NULL;

        if (path && *path) {
            FILE *f = fopen(path, "r");
            if (f) {
                /*
                 * Read line by line.  buf is sized to hold NAME_MAX_LEN chars
                 * plus a newline and NUL.  If a line overflows, it is split by
                 * fgets() into multiple chunks; we detect this by checking
                 * whether the chunk ends with '\n'.  Overlong chunks are
                 * drained and discarded as a single malformed entry.
                 */
                char buf[NAME_MAX_LEN + 2]; /* +1 for '\n', +1 for '\0' */
                int  overlong = 0; /* are we draining an overlong line? */

                while (fgets(buf, (int)sizeof(buf), f)) {
                    size_t len = strlen(buf);
                    int    has_newline = (len > 0 &&
                                          (buf[len-1] == '\n' || buf[len-1] == '\r'));

                    /* Strip trailing CR/LF. */
                    while (len > 0 &&
                           (buf[len-1] == '\n' || buf[len-1] == '\r'))
                        buf[--len] = '\0';

                    if (!has_newline && !feof(f)) {
                        /* Line is longer than our buffer — mark and drain. */
                        overlong = 1;
                        continue;
                    }

                    if (overlong) {
                        /* Last chunk of an overlong line — discard entire entry. */
                        overlong = 0;
                        continue;
                    }

                    /* Skip blank lines and '#' comments. */
                    if (len == 0 || buf[0] == '#')
                        continue;

                    if (protected_count < MAX_PROTECTED) {
                        strncpy(protected_names[protected_count], buf, NAME_MAX_LEN);
                        protected_names[protected_count][NAME_MAX_LEN - 1] = '\0';
                        protected_count++;
                    }
                    /* Names beyond MAX_PROTECTED are silently ignored (v1). */
                }
                fclose(f);
            }
        }
    }
    /* in_shim remains 1; the caller (shim_init or getenv) resets it. */
}

__attribute__((constructor))
static void shim_init(void)
{
    /*
     * Set in_shim before pthread_once so that any getenv() call made by
     * another library's constructor — or by dlsym/fopen inside do_init —
     * on *this thread* takes the bypass branch and does not re-enter init.
     */
    in_shim = 1;
    pthread_once(&init_once, do_init);
    in_shim = 0;
}

/* ── JSON string escaping ────────────────────────────────────────────────── */

/*
 * Writes an escaped JSON string body (without surrounding quotes) for `src`
 * into `dst[0..dst_size-1]`.  Returns the number of bytes written.
 *
 * If the name is truncated because it wouldn't fit, the output is terminated
 * with the literal string `<truncated>` so forensic readers can detect it.
 * (The closing `"` is always appended by the caller.)
 */
static int json_escape(char *dst, size_t dst_size, const char *src)
{
    static const char hex[] = "0123456789abcdef";
    static const char trunc_marker[] = "<truncated>";
    /* Reserve space for the truncation marker + closing fields. */
    const size_t reserve = sizeof(trunc_marker) - 1 + 1 /* NUL guard */;

    if (!src) {
        /* Caller should never pass NULL name in practice; be defensive. */
        if (dst_size > 4) { memcpy(dst, "null", 4); return 4; }
        return 0;
    }

    int n = 0;
    int truncated = 0;

    for (const char *p = src; *p; p++) {
        unsigned char c = (unsigned char)*p;
        int needed;

        if      (c == '"'  || c == '\\') needed = 2;
        else if (c < 0x20)               needed = 6; /* \u00XX */
        else                             needed = 1;

        if ((size_t)(n + needed) + reserve > dst_size) {
            truncated = 1;
            break;
        }

        if (c == '"') {
            dst[n++] = '\\'; dst[n++] = '"';
        } else if (c == '\\') {
            dst[n++] = '\\'; dst[n++] = '\\';
        } else if (c < 0x20) {
            dst[n++] = '\\';
            dst[n++] = 'u';
            dst[n++] = '0';
            dst[n++] = '0';
            dst[n++] = hex[(c >> 4) & 0xf];
            dst[n++] = hex[c & 0xf];
        } else {
            dst[n++] = (char)c;
        }
    }

    if (truncated) {
        memcpy(dst + n, trunc_marker, sizeof(trunc_marker) - 1);
        n += (int)(sizeof(trunc_marker) - 1);
    }

    return n;
}

/* ── emit one JSONL audit line ────────────────────────────────────────────── */

static void emit(const char *name, int hidden)
{
    if (log_fd < 0) return;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long ns = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;

    pid_t pid = getpid();

    char buf[JSONL_BUF];
    int pos = 0;

    /* {"kind":"env_read","name":" */
    const char prefix[] = "{\"kind\":\"env_read\",\"name\":\"";
    memcpy(buf + pos, prefix, sizeof(prefix) - 1);
    pos += (int)(sizeof(prefix) - 1);

    /* Allow json_escape up to half the buffer; the rest is for suffix + marker. */
    pos += json_escape(buf + pos, sizeof(buf) - (size_t)pos - 80, name);

    /* ","pid":<pid>,"ts":<ns>,"hidden":<bool>}\n */
    /* NOTE: snprintf is not async-signal-safe (POSIX); emit() must never be
     * called from a signal handler.  This is safe here because emit() is only
     * invoked from the getenv wrappers, which are not signal-handler contexts. */
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                    "\",\"pid\":%d,\"ts\":%lld,\"hidden\":%s}\n",
                    pid, ns, hidden ? "true" : "false");

    /* write_all handles EINTR retries; drops on EPIPE/EBADF. */
    if (pos > 0 && pos <= JSONL_BUF)
        write_all(log_fd, buf, (size_t)pos);
}

/* ── wrapped functions ────────────────────────────────────────────────────── */

/*
 * TODO(v2): environ[] direct iteration bypasses getenv entirely.
 * Processes that read char **environ directly (e.g. via execve envp
 * reconstruction or env(1)'s own printing) will not be audited here.
 * Mitigation: expose a wrapped __environ symbol or intercept libc's
 * environ access via a linker script / ELF symbol interposition on
 * the array pointer itself.
 */

__attribute__((visibility("default")))
char *getenv(const char *name)
{
    /*
     * Recursion guard: if in_shim is already 1 on this thread, we are being
     * called re-entrantly (either from inside do_init, from emit, or from
     * real_getenv itself on some libc builds).  Forward directly to the real
     * implementation without logging or protection checks.
     *
     * In the normal (non-reentrant) path we keep in_shim = 1 for the entire
     * duration of this call — including across pthread_once and emit — so
     * that any getenv re-entry triggered by dlsym, fopen, clock_gettime, or
     * the real getenv implementation takes the bypass branch above.
     */
    if (in_shim) {
        if (real_getenv) return real_getenv(name);
        return NULL; /* real_getenv not yet resolved */
    }

    in_shim = 1;

    /* Ensure init has run (pthread_once is a no-op after first completion). */
    pthread_once(&init_once, do_init);
    /* do_init left in_shim = 1; we keep it 1. */

    int hidden = is_protected(name);
    emit(name, hidden);
    char *val = NULL;
    if (!hidden && real_getenv)
        val = real_getenv(name);

    in_shim = 0;
    return val;
}

__attribute__((visibility("default")))
char *secure_getenv(const char *name)
{
    if (in_shim) {
        if (real_secure_getenv) return real_secure_getenv(name);
        return NULL;
    }

    in_shim = 1;
    pthread_once(&init_once, do_init);

    int hidden = is_protected(name);
    emit(name, hidden);
    char *val = NULL;
    if (!hidden) {
        if (real_secure_getenv)
            val = real_secure_getenv(name);
        else if (real_getenv)
            val = real_getenv(name); /* musl fallback: secure_getenv absent, but
                                      * script-jail guests are never setuid, so
                                      * secure_getenv == getenv semantically. */
    }

    in_shim = 0;
    return val;
}

/*
 * __secure_getenv is a deprecated glibc alias for secure_getenv.
 * Wrap it for completeness; applies the same musl fallback as secure_getenv.
 */
__attribute__((visibility("default")))
char *__secure_getenv(const char *name)
{
    if (in_shim) {
        if (real_secure_getenv) return real_secure_getenv(name);
        return NULL;
    }

    in_shim = 1;
    pthread_once(&init_once, do_init);

    int hidden = is_protected(name);
    emit(name, hidden);
    char *val = NULL;
    if (!hidden) {
        if (real_secure_getenv)
            val = real_secure_getenv(name);
        else if (real_getenv)
            val = real_getenv(name); /* musl fallback: see secure_getenv above */
    }

    in_shim = 0;
    return val;
}
