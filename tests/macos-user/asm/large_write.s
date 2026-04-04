// Test: write a large block of data (4096 bytes of 'A' followed by newline)
// Verifies that data segment and larger writes work correctly
.global _main
.align 4
_main:
    // write(1, buf, 4097) - 4096 'A's + newline
    mov x0, #1
    adrp x1, buf@PAGE
    add x1, x1, buf@PAGEOFF
    mov x2, #4097
    mov x16, #4
    svc #0x80

    mov x0, #0
    mov x16, #1
    svc #0x80

.data
.align 4
buf:
    .fill 4096, 1, 0x41     // 4096 'A' characters
    .byte 0x0a               // newline
