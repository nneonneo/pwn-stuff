#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <setjmp.h>
#include <stdint.h>

#include "fancy_hexdump.h"

sigjmp_buf jmp;

static void segv_handler(int signo) {
    siglongjmp(jmp, 1);
}

#define LINELEN 16

int main() {
    uint32_t marker = 0xdeadbeef;

    signal(SIGSEGV, segv_handler);
    signal(SIGBUS, segv_handler);

    uint8_t linebuf[LINELEN];
    volatile uintptr_t linestart = (uintptr_t)&marker;
    linestart &= ~0xf;
    volatile int linepos = 0;

    if(!sigsetjmp(jmp, 0)) {
        for(;;) {
            for(linepos=0; linepos < LINELEN; linepos++) {
                linebuf[linepos] = *(uint8_t *)(linestart + linepos);
            }
            hexdump_line(linestart, linebuf, LINELEN, sizeof(void *), LINELEN);
            linestart += LINELEN;
        }
    }
    hexdump_line(linestart, linebuf, linepos, sizeof(void *), LINELEN);

    return 0;
}
