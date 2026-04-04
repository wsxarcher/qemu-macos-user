// Test: write to both stdout and stderr, exit 0
.global _main
.align 4
_main:
    // write(1, stdout_msg, 15)
    mov x0, #1
    adrp x1, stdout_msg@PAGE
    add x1, x1, stdout_msg@PAGEOFF
    mov x2, #15
    mov x16, #4
    svc #0x80

    // write(2, stderr_msg, 15)
    mov x0, #2
    adrp x1, stderr_msg@PAGE
    add x1, x1, stderr_msg@PAGEOFF
    mov x2, #15
    mov x16, #4
    svc #0x80

    // exit(0)
    mov x0, #0
    mov x16, #1
    svc #0x80

.data
stdout_msg: .ascii "stdout output\n\0"
stderr_msg: .ascii "stderr output\n\0"
