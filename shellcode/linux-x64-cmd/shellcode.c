char shellcode[] = "H1\300H\215=\30\0\0\0PTZH\215O\vQH\215O\bQH\215O\5QT^\260;\17\5/bin/sh\0-c\0ls -la\0";

#include <sys/mman.h>
#include <string.h>
int main() {
    int (*sc)() = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(sc, shellcode, sizeof(shellcode));
    return sc();
}
