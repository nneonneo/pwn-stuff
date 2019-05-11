all: malloc_preload.so

%.so: %.c
	gcc $< -o $@ -ldl -shared -D_GNU_SOURCE -fPIC -Wall
