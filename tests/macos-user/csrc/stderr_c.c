/* Test: write to stderr and stdout separately */
#include <stdio.h>
int main(void) {
    fprintf(stdout, "on stdout\n");
    fprintf(stderr, "on stderr\n");
    return 0;
}
