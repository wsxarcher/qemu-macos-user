// Test: stack operations - push/pop values, verify correctness
// Push 1,2,3,4 on stack, pop and sum them, print result "10\n"
.global _main
.align 4
_main:
    // Push values onto stack
    sub sp, sp, #32
    mov x0, #1
    str x0, [sp]
    mov x0, #2
    str x0, [sp, #8]
    mov x0, #3
    str x0, [sp, #16]
    mov x0, #4
    str x0, [sp, #24]

    // Pop and sum
    ldr x0, [sp]
    ldr x1, [sp, #8]
    add x0, x0, x1
    ldr x1, [sp, #16]
    add x0, x0, x1
    ldr x1, [sp, #24]
    add x0, x0, x1
    add sp, sp, #32

    // x0 = 10, convert to "10\n"
    sub sp, sp, #16
    mov w1, #'1'
    strb w1, [sp]
    mov w1, #'0'
    strb w1, [sp, #1]
    mov w1, #'\n'
    strb w1, [sp, #2]

    mov x0, #1
    mov x1, sp
    mov x2, #3
    mov x16, #4
    svc #0x80

    add sp, sp, #16

    mov x0, #0
    mov x16, #1
    svc #0x80
