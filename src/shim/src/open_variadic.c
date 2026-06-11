#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>

extern int script_jail_open_impl(const char *path, int flags, unsigned int mode);
extern int script_jail_openat_impl(int dirfd, const char *path, int flags, unsigned int mode);

int script_jail_open_variadic(const char *path, int flags, ...) {
  int mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  return script_jail_open_impl(path, flags, (unsigned int)mode);
}

int script_jail_openat_variadic(int dirfd, const char *path, int flags, ...) {
  int mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, int);
    va_end(ap);
  }
  return script_jail_openat_impl(dirfd, path, flags, (unsigned int)mode);
}
