char shellcode[] = "1\300H\215=\24\0\0\0PTZH\215O\vQH\215O\bQWT^\260;\17\5/bin/sh\0-c\0ls -la\0";

#include <sys/mman.h>
#include <string.h>
int main() {
    int (*sc)() = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(sc, shellcode, sizeof(shellcode));
    return sc();
}
