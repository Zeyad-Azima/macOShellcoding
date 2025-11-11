bits 64

global _main

_main:
	mov rdi, 27646 ; 1st argument PID
	mov rsi, 9 ; 2nd argument signum
	mov rdx, 0 ; 3rd argument posix
	mov rax, 0x2000025 ; The BSD syscall class entry + 0x25 (which is 37 in hex) kill syscall
	syscall
	
	mov rax, 0x2000001 ; The BSD syscall class entry + exit syscall
	mov rdi, 0 ; arg int rval
	syscall ; invoke/execute syscall
