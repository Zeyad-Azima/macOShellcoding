bits 64

global _main

_main:
	mov rdi, 1 ; stdout for fd argument
	mov rcx, 'Hello' ; put our string value into RCX
	push rcx ; We push our string to the stack
	mov rsi, rsp ; we supply the pointer to our string from RSP to RSI which is buf argument
	mov rdx, 5 ; nbytes argument (our string length)
	mov rax, 0x2000004 ; The BSD syscall class entry + write syscall number
	syscall ; invoke/execute syscall
	
	mov rax, 0x2000001 ; The BSD syscall class entry + exit syscall
	mov rdi, 0 ; arg int rval
	syscall ; invoke/execute syscall
