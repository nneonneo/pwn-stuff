#!/bin/bash -ex

ESCENCODE="./escencode.py"
DIR=escencode_test

mkdir -p $DIR

echo "[+] Making test binary file"
python -c 'import sys; sys.stdout.write("".join(chr(a)+chr(b) for a in xrange(256) for b in xrange(256)))' > $DIR/test.bin


echo "[+] Testing C output"
cat > $DIR/test.c <<EOF
char test[] = 
$($ESCENCODE --style=c -W 80 $DIR/test.bin)
;

#include <stdio.h>

int main() {
    fwrite(test, 1, sizeof(test)-1, stdout);
}
EOF

gcc $DIR/test.c -o $DIR/test.c.exe
$DIR/test.c.exe > $DIR/test.c.bin
cmp $DIR/test.bin $DIR/test.c.bin


echo "[+] Testing Python output"
cat > $DIR/test.py <<EOF
import sys
sys.stdout.write(
$($ESCENCODE --style=python -W 80 $DIR/test.bin)
)
EOF

python $DIR/test.py > $DIR/test.py.bin
cmp $DIR/test.bin $DIR/test.py.bin


echo "[+] Testing Echo output"
cat > $DIR/test.echo.sh <<EOF
$($ESCENCODE --style=echo $DIR/test.bin)
EOF

bash $DIR/test.echo.sh > $DIR/test.echo.bin
cmp $DIR/test.bin $DIR/test.echo.bin


