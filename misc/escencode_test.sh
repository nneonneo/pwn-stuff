#!/bin/bash -e

ESCENCODE="../escencode.py"
DIR=escencode_test

mkdir -p $DIR
cd $DIR

echo "[+] Making test files"
python -c 'import sys; sys.stdout.write("".join(chr(a)+chr(b) for a in xrange(256) for b in xrange(256)))' > test.bin


echo "[+] Testing C output"
cat > test.c <<EOF
char test[] = 
$($ESCENCODE --style=c -W 80 test.bin)
;

#include <stdio.h>

int main() {
    fwrite(test, 1, sizeof(test)-1, stdout);
}
EOF

gcc test.c -o test.c.exe
./test.c.exe > test.c.bin
cmp test.bin test.c.bin


echo "[+] Testing Python output"
cat > test.py <<EOF
import sys
sys.stdout.write(
$($ESCENCODE --style=python -W 80 test.bin)
)
EOF

python test.py > test.py.bin
cmp test.bin test.py.bin


echo "[+] Testing Ruby output"
cat > test.rb <<EOF
print $($ESCENCODE --style=ruby -W 80 test.bin)
EOF

ruby test.rb > test.rb.bin
cmp test.bin test.rb.bin


echo "[+] Testing Java output"
cat > test.java <<EOF
public class test {
    public static final void main(String[] args) {
        try {
            System.out.write( ($($ESCENCODE --style=java -W 80 test.bin)).getBytes("ISO-8859-1"));
        } catch(Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
EOF

javac test.java
java test > test.java.bin
cmp test.bin test.java.bin


echo "[+] Testing Echo output"
cat > test.echo.sh <<EOF
$($ESCENCODE --style=echo -W 80 test.bin)
EOF

bash test.echo.sh > test.echo.bin
cmp test.bin test.echo.bin


echo '[+] All tests passed!'
