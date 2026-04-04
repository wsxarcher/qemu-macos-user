// Test: conditional logic - find max of 3 numbers (17, 42, 23) = 42
// Print "42\n"
.global _main
.align 4
_main:
    mov x0, #17         // a
    mov x1, #42         // b
    mov x2, #23         // c

    // max = a
    mov x3, x0

    // if b > max: max = b
    cmp x1, x3
    csel x3, x1, x3, gt

    // if c > max: max = c
    cmp x2, x3
    csel x3, x2, x3, gt

    // x3 = 42, convert to decimal
    mov x9, x3
    mov x4, #10
    udiv x5, x9, x4     // x5 = 4 (tens)
    msub x6, x5, x4, x9  // x6 = 2 (ones)

    sub sp, sp, #16
    add w5, w5, #'0'
    add w6, w6, #'0'
    strb w5, [sp]
    strb w6, [sp, #1]
    mov w7, #'\n'
    strb w7, [sp, #2]

    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80
