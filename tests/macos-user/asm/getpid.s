// Test: getpid syscall - print PID to stdout
// SYS_getpid = 20 on macOS
.global _main
.align 4
_main:
    // getpid()
    mov x16, #20
    svc #0x80
    // x0 = pid

    // Convert to decimal and print
    mov x9, x0           // save pid
    sub sp, sp, #32
    add x10, sp, #20     // write position (right to left)
    mov w11, #'\n'
    strb w11, [x10]      // trailing newline
    sub x10, x10, #1

    // Handle pid=0 edge case
    cmp x9, #0
    b.ne convert
    mov w11, #'0'
    strb w11, [x10]
    sub x10, x10, #1
    b print

convert:
    mov x12, #10
digit_loop:
    cbz x9, print
    udiv x13, x9, x12
    msub x14, x13, x12, x9
    add w14, w14, #'0'
    strb w14, [x10]
    sub x10, x10, #1
    mov x9, x13
    b digit_loop

print:
    add x10, x10, #1     // x10 = start of string
    add x11, sp, #21     // x11 = past newline
    sub x2, x11, x10     // length

    mov x0, #1
    mov x1, x10
    mov x16, #4
    svc #0x80

    add sp, sp, #32

    mov x0, #0
    mov x16, #1
    svc #0x80
