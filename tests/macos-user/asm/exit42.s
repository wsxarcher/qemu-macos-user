// Test: exit with code 42
.global _main
.align 4
_main:
    mov x0, #42
    mov x16, #1        // SYS_exit
    svc #0x80
