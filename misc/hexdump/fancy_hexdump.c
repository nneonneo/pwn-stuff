#include <stdio.h>

#include "fancy_hexdump.h"

/* Colorized hexdump for the 21st century. */

#define COLOR_BLACK 0
#define COLOR_RED 1
#define COLOR_GREEN 2
#define COLOR_YELLOW 3
#define COLOR_BLUE 4
#define COLOR_MAGENTA 5
#define COLOR_CYAN 6
#define COLOR_WHITE 7
#define COLOR_DEFAULT 9

static void set_color(int fg, int bg) {
    static int old_fg=-1, old_bg=-1;
    if(old_fg == fg && old_bg == bg)
        return;

    printf("\x1b[");
    if(fg != old_fg && bg != old_fg) {
        printf("3%d;4%dm", fg, bg);
    } else if(fg != old_fg) {
        printf("3%dm", fg);
    } else {
        printf("4%dm", bg);
    }
    old_fg = fg;
    old_bg = bg;
}

static void null_color(void) {
    set_color(COLOR_DEFAULT, COLOR_DEFAULT);
}

static void char_color(uint8_t ch) {
    if(ch == 0) {
        set_color(COLOR_WHITE, COLOR_DEFAULT);
    } else if(ch >= 127) {
        set_color(COLOR_CYAN, COLOR_DEFAULT);
    } else {
        set_color(COLOR_DEFAULT, COLOR_DEFAULT);
    }
}

static void print_char(uint8_t ch) {
    if(ch < 32) {
        printf(".");
    } else if(ch < 127) {
        printf("%c", ch);
    } else if(ch < 192) {
        printf(".");
    } else {
        printf("%c%c", (ch >> 6) | 0xc0, (ch & 0x3f) | 0x80);
    }
}

void hexdump_line(uintptr_t addr, uint8_t *buf, int nbytes, int grouping, int maxbytes) {
    if(!nbytes)
        return;

    int i=0;
    null_color();
    set_color(COLOR_BLUE, COLOR_DEFAULT);
    printf("0x%0*lx: ", (int)sizeof(void *)*2, addr);
    for(i=0; i<maxbytes; i++) {
        if(grouping && (i % grouping == 0)) {
            null_color();
            printf(" ");
        }

        if(i < nbytes) {
            char_color(buf[i]);
            printf("%02x", buf[i]);
        } else {
            null_color();
            printf("  ");
        }
    }

    null_color();
    printf("  ");

    for(i=0; i<maxbytes; i++) {
        if(i < nbytes) {
            char_color(buf[i]);
            print_char(buf[i]);
        } else {
            null_color();
            printf(" ");
        }
    }
    null_color();
    printf("\n");
}

void hexdump(uintptr_t addr, uint8_t *buf, int nbytes, int grouping, int linebytes) {
    int cur;
    for(cur=0; cur<nbytes; cur+=linebytes) {
        hexdump_line(addr+cur, buf+cur, nbytes-cur, grouping, linebytes);
    }
}

#ifdef TEST
int main() {
    uint8_t buf[256];
    for(int i=0; i<256; i++) {
        buf[i] = i;
    }
    hexdump((uintptr_t)buf, buf, 256, 2, 16);
    return 0;
}
#endif
