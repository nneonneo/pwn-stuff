#include <stdint.h>

void hexdump_line(uintptr_t addr, uint8_t *buf, int nbytes, int grouping, int maxbytes);
void hexdump(uintptr_t addr, uint8_t *buf, int nbytes, int grouping, int linebytes);
