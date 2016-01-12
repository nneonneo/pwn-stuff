all: malloc_preload.so

%.so: %.c
	gcc $< -m32 -o $@ -ldl -shared -D_GNU_SOURCE -fPIC -Wall
