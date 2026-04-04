// Test: memory fill and verify - fill a stack buffer with a pattern,
// verify it, then print "OK\n"
.global _main
.align 4
_main:
    sub sp, sp, #256

    // Fill buffer with pattern: buf[i] = i & 0xFF
    mov x0, #0          // index
fill_loop:
    and w1, w0, #0xFF
    strb w1, [sp, x0]
    add x0, x0, #1
    cmp x0, #256
    b.lt fill_loop

    // Verify pattern
    mov x0, #0
verify_loop:
    ldrb w1, [sp, x0]
    and w2, w0, #0xFF
    cmp w1, w2
    b.ne fail
    add x0, x0, #1
    cmp x0, #256
    b.lt verify_loop

    // Success - print "OK\n"
    add sp, sp, #256
    mov x0, #1
    adrp x1, ok_msg@PAGE
    add x1, x1, ok_msg@PAGEOFF
    mov x2, #3
    mov x16, #4
    svc #0x80

    mov x0, #0
    mov x16, #1
    svc #0x80

fail:
    add sp, sp, #256
    mov x0, #1
    adrp x1, fail_msg@PAGE
    add x1, x1, fail_msg@PAGEOFF
    mov x2, #5
    mov x16, #4
    svc #0x80

    mov x0, #1
    mov x16, #1
    svc #0x80

.data
ok_msg: .ascii "OK\n"
fail_msg: .ascii "FAIL\n"
