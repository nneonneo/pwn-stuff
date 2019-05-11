#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#define PRINT(x) write(2, x, strlen(x))
#define MY_PRINTF(bufsz, fmt, ...) { char buf[bufsz]; sprintf(buf, "[pid %d] " fmt, getpid(), ##__VA_ARGS__); PRINT(buf); }

void *malloc(size_t size) {
	static void *(*fn)(size_t);
	if(!fn) fn = dlsym(RTLD_NEXT, "malloc");

	void *ptr = fn(size);

	MY_PRINTF(256, "malloc(%zd) = %p\n", size, ptr);
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

	void *ptr = fn(size, size2);

	MY_PRINTF(256, "calloc(%zd, %zd) = %p\n", size, size2, ptr);
	return ptr;
}

void *realloc(void *optr, size_t size) {
	static void *(*fn)(void *, size_t);
	if(!fn) fn = dlsym(RTLD_NEXT, "realloc");

	void *ptr = fn(optr, size);

	MY_PRINTF(256, "realloc(%p, %zd) = %p\n", optr, size, ptr);
	return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
	static int (*fn)(void **, size_t, size_t);
	if(!fn) {
		fn = dlsym(RTLD_NEXT, "posix_memalign");
	}

	int res = fn(memptr, alignment, size);

	if(res == 0) {
		MY_PRINTF(256, "posix_memalign(%p, %zd, %zd) = %p\n", memptr, alignment, size, *memptr);
	} else {
		MY_PRINTF(256, "posix_memalign(%p, %zd, %zd) = error (%d)\n", memptr, alignment, size, errno);
	}

	return res;
}

void free(void *ptr) {
	static void (*fn)(void *);
	if(!fn) fn = dlsym(RTLD_NEXT, "free");

	MY_PRINTF(256, "free(%p) [0x%x bytes]\n", ptr, malloc_usable_size(ptr));

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

	MY_PRINTF(32, "time() = %ld\n", ret);

	if(t) *t = ret;
	return ret;
}

int rand(void) {
	static int(*fn)(void);
	if(!fn) fn = dlsym(RTLD_NEXT, "rand");

	int ret = fn();

	MY_PRINTF(32, "rand() = %d\n", ret);
	return ret;
}
