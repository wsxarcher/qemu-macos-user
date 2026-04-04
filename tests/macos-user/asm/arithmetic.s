// Test: integer arithmetic - compute (10 + 20) * 3 - 5 = 85, print result
.global _main
.align 4
_main:
    mov x0, #10
    mov x1, #20
    add x0, x0, x1       // x0 = 30
    mov x1, #3
    mul x0, x0, x1        // x0 = 90
    mov x1, #5
    sub x0, x0, x1        // x0 = 85

    // Convert x0 to decimal string on stack
    // We know result is 85, so output "85\n"
    // Divide by 10 to get digits
    mov x9, x0            // save result
    mov x1, #10
    udiv x2, x9, x1       // x2 = 8 (tens)
    msub x3, x2, x1, x9   // x3 = 5 (ones)

    // Build string on stack
    sub sp, sp, #16
    add x2, x2, #'0'
    add x3, x3, #'0'
    strb w2, [sp]
    strb w3, [sp, #1]
    mov w4, #'\n'
    strb w4, [sp, #2]

    // write(1, sp, 3)
    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80
