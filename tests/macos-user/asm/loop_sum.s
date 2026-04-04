// Test: loop counting - sum 1..10 = 55, print "55\n"
.global _main
.align 4
_main:
    mov x0, #0          // accumulator
    mov x1, #1          // counter

loop:
    add x0, x0, x1
    add x1, x1, #1
    cmp x1, #11
    b.lt loop

    // x0 = 55
    // Convert to decimal
    mov x9, x0
    mov x1, #10
    udiv x2, x9, x1     // x2 = 5 (tens)
    msub x3, x2, x1, x9  // x3 = 5 (ones)

    sub sp, sp, #16
    add x2, x2, #'0'
    add x3, x3, #'0'
    strb w2, [sp]
    strb w3, [sp, #1]
    mov w4, #'\n'
    strb w4, [sp, #2]

    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80
