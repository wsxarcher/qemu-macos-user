// Test: multiple writes to stdout, verifying sequential I/O
.global _main
.align 4
_main:
    // Write "line 1\n"
    mov x0, #1
    adrp x1, line1@PAGE
    add x1, x1, line1@PAGEOFF
    mov x2, #7
    mov x16, #4
    svc #0x80

    // Write "line 2\n"
    mov x0, #1
    adrp x1, line2@PAGE
    add x1, x1, line2@PAGEOFF
    mov x2, #7
    mov x16, #4
    svc #0x80

    // Write "line 3\n"
    mov x0, #1
    adrp x1, line3@PAGE
    add x1, x1, line3@PAGEOFF
    mov x2, #7
    mov x16, #4
    svc #0x80

    mov x0, #0
    mov x16, #1
    svc #0x80

.data
line1: .ascii "line 1\n"
line2: .ascii "line 2\n"
line3: .ascii "line 3\n"
