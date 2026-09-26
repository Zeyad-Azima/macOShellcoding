.global _main
.align 2

_main:
	sub sp, sp, #16         ; make room on the stack for our string
	movz x9, #0x6548        ; build our string: 'H','e' chunk
	movk x9, #0x6c6c, lsl #16 ; 'l','l' chunk
	movk x9, #0x006f, lsl #32 ; 'o' chunk + terminator zeros
	stur x9, [sp]           ; store our string on the stack
	mov x1, sp              ; buf argument -> pointer to our string
	mov x2, #5              ; nbytes argument (string length)
	mov x0, #1              ; fd argument (stdout)
	movz x16, #4            ; write syscall number
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2 -> X16 = 0x2000004
	svc #0x80               ; invoke/execute the syscall

	movz x16, #1            ; exit syscall number
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2 -> X16 = 0x2000001
	mov x0, #0              ; arg int rval
	svc #0x80               ; invoke/execute the syscall
