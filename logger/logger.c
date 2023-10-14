#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>

static char buf1[8192];
static char buf2[8192];

int
chmod(const char *pathname, mode_t mode)
{
    int (*f)(const char *, mode_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path = NULL;

    f = dlsym(RTLD_NEXT, "chmod");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if (f) ret = f(pathname, mode);
    dprintf(ifd, "[logger] chmod(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int
chown(const char *pathname, uid_t owner, gid_t group)
{
    int (*f)(const char *, uid_t, gid_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path = NULL;

    f = dlsym(RTLD_NEXT, "chown");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if (f) ret = f(pathname, owner, group);
    dprintf(ifd, "[logger] chown(\"%s\", %u, %u) = %d\n", path, owner, group, ret);
    return ret;
}

int
close(int fd)
{
    int (*f)(int) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    pid_t p;
    const char *path;

    f = dlsym(RTLD_NEXT, "close");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    p = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", p, fd);

    path = realpath(buf1, buf2);
    path = buf2; 

    if (f) ret = f(fd);
    dprintf(ifd, "[logger] close(\"%s\") = %d\n", buf2, ret);
    return ret;
}

int
creat(const char *pathname, mode_t mode)
{
    int (*f)(const char *, mode_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path = NULL;

    f = dlsym(RTLD_NEXT, "creat");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if (f) ret = f(pathname, mode);
    dprintf(ifd, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int
fclose(FILE *stream)
{
    int (*f)(FILE *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    int fd;
    pid_t p;
    const char *path;

    f = dlsym(RTLD_NEXT, "fclose");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    fd = fileno(stream);
    p = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", p, fd);

    path = realpath(buf1, buf2);
    path = buf2;

    if (f) ret = f(stream);
    dprintf(ifd, "[logger] fclose(\"%s\") = %d\n", path, ret);
    return ret;
}

FILE *
fopen(const char *filename, const char *mode)
{
    FILE *(*f)(const char *, const char *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    FILE *ret = NULL;
    const char *path;

    f = dlsym(RTLD_NEXT, "fopen");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(filename, buf1);
    path = buf1;

    if (f) ret = f(filename, mode);
    dprintf(ifd, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    return ret;
}

size_t
fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t (*f)(void *, size_t, size_t, FILE *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    size_t ret = 0;
    size_t i = 0;
    char *p = (char *) ptr;
    int fd;
    pid_t pid;
    const char *path;
    size_t num;
    char cbuf[33] = {0};

    f = dlsym(RTLD_NEXT, "fread");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    fd = fileno(stream);
    pid = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", pid, fd);

    path = realpath(buf1, buf2);
    path = buf2;

    if (f) ret = f(ptr, size, nmemb, stream);
    
    num = ret * size;
    num = num <= 32 ? num : 32;
    for (i = 0; i < num; i++) {
        if (isprint(p[i])) cbuf[i] = p[i];
        else cbuf[i] = '.';
    }
    cbuf[i] = '\0';

    dprintf(ifd, "[logger] fread(\"%s\", %lu, %lu, \"%s\") = %lu\n", cbuf, size, nmemb, path, ret);
    return ret;
}

size_t
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t (*f)(const void *, size_t, size_t, FILE *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    size_t ret = 0;
    size_t i = 0;
    const char *p = (const char *) ptr;
    int fd;
    pid_t pid;
    const char *path;
    size_t num;
    char cbuf[33] = {0};

    f = dlsym(RTLD_NEXT, "fwrite");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    fd = fileno(stream);
    pid = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", pid, fd);

    path = realpath(buf1, buf2);
    path = buf2;

    if (f) ret = f(ptr, size, nmemb, stream);
    
    num = ret * size;
    num = num <= 32 ? num : 32;
    for (i = 0; i < num; i++) {
        if (isprint(p[i])) cbuf[i] = p[i];
        else cbuf[i] = '.';
    }
    cbuf[i] = '\0';

    dprintf(ifd, "[logger] fwrite(\"%s\", %lu, %lu, \"%s\") = %lu\n", cbuf, size, nmemb, path, ret);
    return ret;
}

int
open(const char *pathname, int flags, ...)
{
    int (*f)(const char *, int, ...) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    va_list ap;
    mode_t mode = 0;
    const char *path;

    f = dlsym(RTLD_NEXT, "open");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = f(pathname, flags, mode);
    }
    else {
        mode = 0;
        ret = f(pathname, flags);
    }

    dprintf(ifd, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
    return ret;
}

ssize_t
read(int fd, void *buf, size_t count)
{
    ssize_t (*f)(int, void *, size_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    ssize_t ret = 0;
    pid_t pid;
    const char *path;
    char *p = (char *) buf;
    char cbuf[33] = {0};
    ssize_t num = 0;
    ssize_t i;

    f = dlsym(RTLD_NEXT, "read");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    pid = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", pid, fd);

    path = realpath(buf1, buf2);
    path = buf2;

    if (f) ret = f(fd, buf, count);

    if (ret > 0) num = ret;
    else num = 0;
    num = num <= 32 ? num : 32;
    for (i = 0; i < num; i++) {
        if (isprint(p[i])) cbuf[i] = p[i];
        else cbuf[i] = '.';
    }
    cbuf[i] = '\0';

    dprintf(ifd, "[logger] read(\"%s\", \"%s\", %lu) = %ld\n", path, cbuf, count, ret);
    return ret;
}

int
remove(const char *pathname)
{
    int (*f)(const char *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path;

    f = dlsym(RTLD_NEXT, "remove");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if (f) ret = f(pathname);

    dprintf(ifd, "[logger] remove(\"%s\") = %d\n", path, ret);
    return ret;
}

int
rename(const char *oldpath, const char *newpath)
{
    int (*f)(const char *, const char *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path1, *path2;

    f = dlsym(RTLD_NEXT, "rename");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path1 = realpath(oldpath, buf1);
    path1 = buf1;

    path2 = realpath(newpath, buf2);
    path2 = buf2;

    if (f) ret = f(oldpath, newpath);

    dprintf(ifd, "[logger] rename(\"%s\", \"%s\") = %d\n", path1, path2, ret);
    return ret; 
}

FILE *
tmpfile(void)
{
    FILE *(*f)(void) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    FILE *ret = NULL;

    f = dlsym(RTLD_NEXT, "tmpfile");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    if (f) ret = f();

    dprintf(ifd, "[logger] tmpfile() = %p\n", ret);
    return ret;
}

ssize_t
write(int fd, const void *buf, size_t count)
{
    ssize_t (*f)(int, const void *, size_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    ssize_t ret = 0;
    pid_t pid;
    const char *path;
    const char *p = (const char *) buf;
    char cbuf[33] = {0};
    ssize_t num = 0;
    ssize_t i;

    f = dlsym(RTLD_NEXT, "write");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    pid = getpid();
    sprintf(buf1, "/proc/%d/fd/%d", pid, fd);

    path = realpath(buf1, buf2);
    path = buf2;

    if (f) ret = f(fd, buf, count);

    if (ret > 0) num = ret;
    else num = 0;
    num = num <= 32 ? num : 32;
    for (i = 0; i < num; i++) {
        if (isprint(p[i])) cbuf[i] = p[i];
        else cbuf[i] = '.';
    }
    cbuf[i] = '\0';

    dprintf(ifd, "[logger] write(\"%s\", \"%s\", %lu) = %ld\n", path, cbuf, count, ret);
    return ret;
}

int
creat64(const char *pathname, mode_t mode)
{
    int (*f)(const char *, mode_t) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    const char *path = NULL;

    f = dlsym(RTLD_NEXT, "creat64");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if (f) ret = f(pathname, mode);
    dprintf(ifd, "[logger] creat64(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int
open64(const char *pathname, int flags, ...)
{
    int (*f)(const char *, int, ...) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    int ret = 0;
    va_list ap;
    mode_t mode = 0;
    const char *path;

    f = dlsym(RTLD_NEXT, "open64");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(pathname, buf1);
    path = buf1;

    if ((flags & O_CREAT) || (flags & O_TMPFILE)) {
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = f(pathname, flags, mode);
    }
    else {
        mode = 0;
        ret = f(pathname, flags);
    }

    dprintf(ifd, "[logger] open64(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
    return ret;
}

FILE *
tmpfile64(void)
{
    FILE *(*f)(void) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    FILE *ret = NULL;

    f = dlsym(RTLD_NEXT, "tmpfile64");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    if (f) ret = f();

    dprintf(ifd, "[logger] tmpfile64() = %p\n", ret);
    return ret;
}

FILE *
fopen64(const char *filename, const char *mode)
{
    FILE *(*f)(const char *, const char *) = NULL;
    int ifd = 0;
    char *cfd = NULL;
    FILE *ret = NULL;
    const char *path;

    f = dlsym(RTLD_NEXT, "fopen64");
    cfd = getenv("UNIX_HW2_FD");
    if (cfd) ifd = (int) strtol(cfd, NULL, 10);
    else ifd = 2;

    path = realpath(filename, buf1);
    path = buf1;

    if (f) ret = f(filename, mode);
    dprintf(ifd, "[logger] fopen64(\"%s\", \"%s\") = %p\n", path, mode, ret);
    return ret;
}