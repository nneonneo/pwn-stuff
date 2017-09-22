# Memory allocators for exploit developers

This post will help you understand memory allocators in more depth, enabling you to use heap corruption vulnerabilities to achieve exploitation. Our focus is on the glibc allocator, but the general principles will be applicable to most memory allocators.

Details on the glibc allocator are taken from glibc's [malloc/malloc.c](http://code.metager.de/source/xref/gnu/glibc/malloc/malloc.c). This is a fairly complex file to read, and it is hoped that this document will result in fewer trips to read that source code :)

You can grab a local copy of `glibc` using `git clone git://sourceware.org/git/glibc.git`.

Throughout, we'll let `SIZE_T` denote `sizeof(size_t)`: 4 on x86, and 8 on x64.

## malloc basics

The `malloc` API is perhaps one of the simplest APIs anywhere in C. It consists essentially of three basic functions:

```c
void *malloc(size_t bytes);
void free(void *mem);
void *realloc(void *mem, size_t newbytes);
```

(Commonly, `calloc` and `memalign`, where present, are implemented as variations of these functions).

`malloc` and `free` operate on the *heap*, which is often just a single contiguous chunk of memory. Classically, it was allocated right after the end of the program's load segments (i.e. after `.text`, `.data` and `.bss`), but more recent systems will often randomize the heap's starting address to make attacks more difficult. The heap is placed far away as possible from the stack and other loaded libraries to give it more room to grow.

> Side-note: Observations on ASLR
> 
> These addresses were observed on a live system with the following `uname`:
> 
>     3.13.0-46-generic #79-Ubuntu SMP Tue Mar 10 20:06:50 UTC 2015 x86_64
> 
> The heap starts on a random page between 0 and 0x2000000 bytes after the end of the program's last load segment. For example, a program that ends at 0x804c000 could have a heap starting on any page from 0x804c000 to 0xa04b000. This is 13 bits of randomness. This is true for both 32-bit and 64-bit binaries on my system (despite the fact that the 64-bit binary could be using a lot more randomness).
> 
> 13 bits is definitely bruteforceable; you would only need 4096 tries on average to guess the heap's base address.

## Heap layout

It is the goal of the `malloc` implementation to parcel out the heap into allocated chunks for the program to use, and also to manage the heap to avoid memory fragmentation (allocated chunks scattered throughout the heap). Most implementations also contain optimizations to speed up certain patterns of allocations (e.g. frequent allocations and deallocations of small objects).

`glibc` organizes its heap into a series of *chunks*. A chunk, at its most basic, is just a `size` value (a `size_t`) followed by `data`. Data addresses are always aligned to a multiple of `2*SIZE_T` bytes - 8 bytes on x86, 16 bytes on x64.

`glibc` makes all chunk sizes a multiple of `2*SIZE_T` bytes. The usable space in each chunk is always `SIZE_T` bytes less than the chunk size.

These chunks are concatenated end-to-end to form the entirety of the heap. Notably, there is no padding: all incoming allocation requests are adjusted so that the alignment requirements are fulfilled. Chunks come in three basic flavours:

- Allocated chunks: an allocated chunk consists of nothing besides the `size` and `data` fields, with the entirety of the `data` field devoted to the program's data:

    ```c
    size_t size;
    char data[size];
    ```

- Tiny free chunk: a tiny free chunk (also known as a "fastbin" chunk) has a single forward pointer to the next free chunk of the same size:

    ```c
    size_t size;
    chunk *next_free;
    char unused[size-SIZE_T];
    ```

- Small free chunk: a small free chunk has both a backwards and forwards list pointer (which may point to chunks of varying size, or to the chunk head inside `libc`), as well as a footer word containing its size:

    ```c
    size_t size;
    chunk *next;
    chunk *prev;
    char unused[size-3*SIZE_T];
    size_t size_footer; // == size
    ```
- Large free chunk: a large free chunk has the fields of a small free chunk, and a pair of `nextsize` values to track the size of the next and previous chunks in its bin:

    ```c
    size_t size;
    chunk *next;
    chunk *prev;
    size_t nextsize;
    size_t prevsize;
    char unused[size-5*SIZE_T];
    size_t size_footer; // == size
    ```

The `tiny` and `small` thresholds are adjustable. The defaults are:

- Tiny: `<= 16*SIZE_T` - 64 bytes on x86 and 128 bytes on x64
- Small: `<= 64*2*SIZE_T` - 512 bytes on x86 and 1024 bytes on x64

`malloc` optimizes allocations of these small chunks because they are the most common kinds of allocations (commonly used for small data structures, such as list elements, as well as short strings).

Technically, there is another type of chunk, the `mmap` chunk. These chunks are not in the heap at all, and are always allocated (they are `munmap`'d when freed). Because they aren't in the heap, there usually isn't anything bordering an `mmap` chunk and so they don't tend to be very useful for exploitation. The cutoff for `mmap` chunks starts at 128KB, but increases if `mmap` chunks are freed (up to a max of 32 MB on 32-bit or 64 MB on 64-bit).

`glibc` also uses the bottom two bits of the `size` value as flag bits (these two bits of the actual size are always zero due to the alignment requirement). Bit #1 indicates that the chunk is `mmap`ed (and thus not even on the heap at all). Bit #0 is *unset* if the previous chunk is a small or large free chunk.

> Side-note: Differences from `malloc.c`
> 
> My descriptions here are a bit different from what glibc's `malloc.c` says. `malloc.c` says that the low bit is an "in use" bit and that the previous size is somehow "part" of the current chunk. These are both quite misleading, so here I've opted for a simpler (yet still correct) view.

In a healthy (read: not corrupted) heap, non-tiny (non-fast) free chunks will never be adjacent to another non-fast free chunk because they are always coalesced whenever possible.

After running a program like this (32-bit):

```c
char *a = malloc(28);
char *b = malloc(16);
char *c = malloc(20);
char *d = malloc(256);
char *e = malloc(512);
free(b);
free(c);
free(d);
```

you will see a heap like this:

        hexaddr value       meaning
        1000    0           unused (bottom of heap)
    
        1004    0x21        allocated chunk a: size
    a:  1008    ...         allocated chunk a: data
    
        1024    0x19        tiny free chunk b: size
    b:  1028    0           tiny free chunk b: next
    
        103c    0x19        tiny free chunk c: size
    c:  1040    0x1020      tiny free chunk c: next
    
        1054    0x109       small free chunk d: size
    d:  1058    0xf0ae1230  small free chunk d: next (chunk header in libc)
        105c    0xf0ae1230  small free chunk d: prev (chunk header in libc)
        ...     ...
        1158    0x108       small free chunk d: size_footer
    
        115c    0x208       allocated chunk e: size
    e:  1160    ...         allocated chunk e: data
    
        1364    0x20ca1     large free chunk TOP: size


Note that at 0x1040, the pointer points to 0x1020. In glibc, chunk pointers point to the footer of the previous chunk (though the footer does not have meaning unless the previous chunk is a large free chunk).

When tiny chunks are freed, they are placed into a "fastbin" according to their size. Each fastbin is a singly-linked list of free chunks, with the head of the list stored in the `arena` structure within libc. The most recently freed chunk is at the head of the list; thus, allocating an object right after freeing an object of the same size will give you back the first object's address.

When non-tiny chunks are freed, they are first coalesced with adjacent non-tiny free chunks, then placed in a regular "bin", which is a circular doubly-linked list of free chunks. There is an "unsorted" bin where most chunks go, which is just a big list of random non-tiny free chunks. Due to the circular list property, non-tiny free chunks can be used to leak a valuable `libc` address if corrupted properly.

## Heap corruption

Since the heap is simply a bunch of chunks all packed together, overflowing off the end of a any heap chunk's data will result in heap corruption. This is the most common way to corrupt the heap. Common bugs that lead to corruption include:

- One null byte overwrite, commonly due to forgetting to allocate enough for a string's null terminator:

    ```c
    char *s2 = malloc(strlen(s)); // one byte too little
    strcpy(s2, s); // oops, one null byte written past the end
    ```

- String overwrite, commonly due to forgetting to null-terminate incoming strings:

    ```c
    char *s3 = malloc(strlen(s) + strlen(t));
    memcpy(s3, s, strlen(s));
    strcat(s3, t); // oops, s3 is not null terminated
    ```

- Longer overwrite, perhaps due to a serious programming error:

    ```c
    char *s4 = malloc(80);
    gets(s4); // oops, gets doesn't bounds check at all
    ```

- Double free, due to a programming error that frees a piece of memory twice

    ```c
    char *a = malloc(24);
    free(a);
    char *b = malloc(24); // allocates the same memory that was just freed
    free(a); // oops, now b is pointing at freed memory
    ```

All are exploitable, even the single null byte overwrite, given the right level of control over allocations and deallocations. Many programs accept user input and allocate based on that, so the degree of control you have can often be quite high.

One important thing to remember is that the size of the data area is always `SIZE_T` more than a multiple of `2*SIZE_T` (8n+4 on x86 and 16n+8 on x64). For example, to trigger a one null byte overwrite in the first example, you can use an input string of length 12 (x86) or 24 (x64).

## Heap exploitation

There are several strategies to achieve exploitation given a heap corruption primitive. Usually, a combination of strategies will be needed.

### Constructing fake chunks

### Overlapping allocations

### Size corruption

### Fastbin corruption

### Leaking heap addresses

### Leaking libc addresses

## Misc tricks

### Controlling `av->top`

9447 CTF 2015, Richard's `search engine` solution

### Double-free trickery

9447 CTF 2015, Robert's `search engine` solution

### Fake misaligned chunks

9447 CTF 2015, Robert's `search engine` solution

### Writing `unsorted_chunks(av)` anywhere in memory using unsorted chunks (small/large)


### Allocating any partially-controlled object with unsorted chunks

	#include <stdlib.h>
	
	int main() {
	    size_t stackbuf[] = {
	        0, 0x90,
	        &stackbuf, &stackbuf,
	        1, 1, 1, 1, 1, 1, 1, 1, 1
	    };
	
	    size_t *buf = malloc(256);
	    malloc(16); // dummy, prevents consolidation
	    free(buf);
	    buf[0] = 0;
	    buf[1] = &stackbuf;
	
	    printf("%p %p %p\n", buf, stackbuf, malloc(128));
	}


