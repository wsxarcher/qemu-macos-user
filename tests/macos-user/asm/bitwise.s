// Test: bitwise operations
// Compute 0xFF00 & 0x0FF0 = 0x0F00 (3840), convert to decimal, print "3840\n"
.global _main
.align 4
_main:
    mov x0, #0xFF00
    mov x1, #0x0FF0
    and x0, x0, x1        // 0x0F00 = 3840

    // Also test OR and XOR
    mov x1, #0x00FF
    orr x2, x0, x1        // 0x0FFF = 4095
    eor x3, x0, x1        // 0x0FFF = 4095

    // Print AND result: 3840
    mov x9, x0
    sub sp, sp, #16
    mov x4, #10

    // 3840 / 10 = 384 rem 0
    udiv x5, x9, x4
    msub x6, x5, x4, x9
    add w6, w6, #'0'
    strb w6, [sp, #3]     // '0'

    // 384 / 10 = 38 rem 4
    mov x9, x5
    udiv x5, x9, x4
    msub x6, x5, x4, x9
    add w6, w6, #'0'
    strb w6, [sp, #2]     // '4'

    // 38 / 10 = 3 rem 8
    mov x9, x5
    udiv x5, x9, x4
    msub x6, x5, x4, x9
    add w6, w6, #'0'
    strb w6, [sp, #1]     // '8'

    // 3
    add w5, w5, #'0'
    strb w5, [sp]          // '3'

    mov w7, #'\n'
    strb w7, [sp, #4]

    mov x0, #1
    mov x1, sp
    mov x2, #5
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80
