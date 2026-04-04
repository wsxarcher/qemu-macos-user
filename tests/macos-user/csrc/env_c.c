/* Test: environment variable access */
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    const char *val = getenv("QEMU_TEST_VAR");
    if (val)
        printf("QEMU_TEST_VAR=%s\n", val);
    else
        printf("QEMU_TEST_VAR=<unset>\n");
    return 0;
}
