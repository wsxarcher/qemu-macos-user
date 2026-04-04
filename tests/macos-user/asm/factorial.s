// Test: function calls using BL/RET - recursive factorial(6) = 720
// Print "720\n"
.global _main
.align 4
_main:
    mov x0, #6
    bl factorial

    // x0 = 720, convert to decimal "720\n"
    mov x9, x0
    sub sp, sp, #16
    mov x4, #10

    // ones: 720 % 10 = 0
    udiv x5, x9, x4
    msub x6, x5, x4, x9
    add w6, w6, #'0'
    strb w6, [sp, #2]

    // tens: 72 % 10 = 2
    mov x9, x5
    udiv x5, x9, x4
    msub x6, x5, x4, x9
    add w6, w6, #'0'
    strb w6, [sp, #1]

    // hundreds: 7
    add w5, w5, #'0'
    strb w5, [sp]

    mov w7, #'\n'
    strb w7, [sp, #3]

    mov x0, #1
    mov x1, sp
    mov x2, #4
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80

// factorial(n) -> n!
// x0 = n, returns in x0
factorial:
    stp x29, x30, [sp, #-16]!
    mov x29, sp

    cmp x0, #1
    b.le base_case

    sub sp, sp, #16
    str x0, [sp]        // save n
    sub x0, x0, #1
    bl factorial         // factorial(n-1)
    ldr x1, [sp]        // restore n
    add sp, sp, #16
    mul x0, x0, x1      // n * factorial(n-1)
    b done

base_case:
    mov x0, #1

done:
    ldp x29, x30, [sp], #16
    ret
