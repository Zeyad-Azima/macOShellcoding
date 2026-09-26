.global _main
.align 2

_main:
	movz x0, #0x8f87        ; 1st argument -> our PID 36743 (0x8F87 in hex)
	                        ; note: `movz` zero-fills the whole 64-bit destination, so upper bits are NULL
	mov x1, #9              ; 2nd argument -> signum, our SIGKILL value
	mov x2, #1              ; 3rd argument -> posix behavior, `!0` for POSIX/BSD
	movz x16, #0x25         ; the kill syscall number 37 (0x25 in hex)
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2
	svc #0x80               ; invoke/execute the syscall

	movz x16, #1            ; exit syscall number
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2
	mov x0, #0              ; arg int rval
	svc #0x80               ; invoke/execute the syscall
