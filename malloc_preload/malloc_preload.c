#include <dlfcn.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#define PRINT(x) write(1, x, strlen(x))
#define MY_PRINTF(bufsz, fmt, ...) { char buf[bufsz]; sprintf(buf, fmt, ##__VA_ARGS__); PRINT(buf); }

void *malloc(size_t size) {
	static void *(*fn)(size_t);
	if(!fn) fn = dlsym(RTLD_NEXT, "malloc");

	void *ptr = fn(size);

	MY_PRINTF(256, "malloc(%zd) = %p\n", size, ptr);
	return ptr;
}

void free(void *ptr) {
	static void (*fn)(void *);
	if(!fn) fn = dlsym(RTLD_NEXT, "free");

	MY_PRINTF(32, "free(%p)\n", ptr);

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
