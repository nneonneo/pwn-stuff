#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>
#include <malloc.h>

static int prev_pid;
static int prev_tid;

#define PRINT(x) write(2, x, strlen(x))
#define PRINTF_TAIL(bufsz, fmt, ...) {   \
  pid_t __pid = getpid();            \
  long __tid = syscall(__NR_gettid); \
  char buf[bufsz];                   \
  if(__pid == prev_pid && __tid == prev_tid) { \
    sprintf(buf, fmt, ##__VA_ARGS__);   \
  } else {                           \
    prev_pid = __pid;                \
    prev_tid = __tid;                \
    sprintf(buf, "[pid %d/%ld] " fmt, __pid, __tid, ##__VA_ARGS__);   \
  }                                  \
  PRINT(buf);                        \
}
#define PRINTF(bufsz, fmt, ...) {    \
  pid_t __pid = getpid();            \
  long __tid = syscall(__NR_gettid); \
  prev_pid = __pid;                  \
  prev_tid = __tid;                  \
  char buf[bufsz];                   \
  if(__pid == __tid) {               \
    sprintf(buf, "[pid %d] " fmt, __pid, ##__VA_ARGS__);   \
  } else {                           \
    sprintf(buf, "[pid %d/%ld] " fmt, __pid, __tid, ##__VA_ARGS__);   \
  }                                  \
  PRINT(buf);                        \
}

int seccomp_load(void *ptr) {
	PRINTF(256, "Ignoring seccomp_load\n");
	return 0;
}

void *malloc(size_t size) {
	static void *(*fn)(size_t);
	if(!fn) fn = dlsym(RTLD_NEXT, "malloc");

	PRINTF(256, "malloc(%zd) = ", size);

	void *ptr = fn(size);

	PRINTF_TAIL(256, "%p\n", ptr);
	return ptr;
}

static void *dlsym_calloc(size_t size, size_t size2) {
	return NULL;
}

void *calloc(size_t size, size_t size2) {
	static void *(*fn)(size_t, size_t);
	if(!fn) {
		/* dlsym calls calloc, so be careful here */
		fn = dlsym_calloc;
		fn = dlsym(RTLD_NEXT, "calloc");
	}

	PRINTF(256, "calloc(%zd, %zd) = ", size, size2);

	void *ptr = fn(size, size2);

	PRINTF_TAIL(256, "%p\n", ptr);
	return ptr;
}

void *realloc(void *optr, size_t size) {
	static void *(*fn)(void *, size_t);
	if(!fn) fn = dlsym(RTLD_NEXT, "realloc");

	PRINTF(256, "realloc(%p, %zd) = ", optr, size);

	void *ptr = fn(optr, size);

	PRINTF_TAIL(256, "%p\n", ptr);
	return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
	static int (*fn)(void **, size_t, size_t);
	if(!fn) {
		fn = dlsym(RTLD_NEXT, "posix_memalign");
	}

	PRINTF(256, "posix_memalign(%p, %zd, %zd) = ", memptr, alignment, size);

	int res = fn(memptr, alignment, size);

	if(res == 0) {
		PRINTF_TAIL(256, "%p\n", *memptr);
	} else {
		PRINTF_TAIL(256, "error (%d)\n", errno);
	}

	return res;
}

void free(void *ptr) {
	static void (*fn)(void *);
	if(!fn) fn = dlsym(RTLD_NEXT, "free");

	PRINTF(256, "free(%p) ", ptr);
	PRINTF_TAIL(256, "[0x%zx bytes]\n", malloc_usable_size(ptr));

	fn(ptr);
}

time_t time(time_t *t) {
	time_t ret = 0;

	int fd = open("time.txt", O_RDWR);
	if(fd >= 0) {
		char buf[16];
		read(fd, buf, 16);
		ret = atoi(buf);
		close(fd);
	}

	PRINTF(32, "time() = %ld\n", ret);

	if(t) *t = ret;
	return ret;
}

int rand(void) {
	static int(*fn)(void);
	if(!fn) fn = dlsym(RTLD_NEXT, "rand");

	int ret = fn();

	PRINTF(32, "rand() = %d\n", ret);
	return ret;
}
