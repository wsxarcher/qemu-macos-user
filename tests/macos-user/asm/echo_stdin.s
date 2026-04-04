// Test: read from stdin, write back to stdout (echo)
.global _main
.align 4
_main:
    sub sp, sp, #256

    // read(0, buf, 256)
    mov x0, #0            // stdin
    mov x1, sp
    mov x2, #256
    mov x16, #3            // SYS_read
    svc #0x80

    // x0 = bytes read (or negative on error)
    cmp x0, #0
    b.le done

    mov x2, x0            // bytes to write
    mov x0, #1            // stdout
    mov x1, sp
    mov x16, #4            // SYS_write
    svc #0x80

done:
    add sp, sp, #256

    mov x0, #0
    mov x16, #1
    svc #0x80
