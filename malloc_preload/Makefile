all: malloc_preload.so malloc_preload-32.so

%-32.so: %.c
	gcc $< -m32 -o $@ -ldl -shared -D_GNU_SOURCE -fPIC -Wall -g

%.so: %.c
	gcc $< -o $@ -ldl -shared -D_GNU_SOURCE -fPIC -Wall -g
