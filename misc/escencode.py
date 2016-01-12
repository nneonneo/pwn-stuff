#!/usr/bin/env python
import sys
import argparse

standard_escapes = {
    '\n': '\\n',
    '\r': '\\r', 
    '\t': '\\t',
}

def hexescape(ch):
    return '\\x%02x' % ch

def encode_char(c, args, hexok=True):
    ch = ord(c)
    if args.no_printable:
        return hexescape(ch)

    if not hexok and c in '0123456789abcdefABCDEF':
        return hexescape(ch)

    if args.style in ('bash', 'echo') and c in '\'"\\$':
        # Hex-escape some special characters to be safe.
        return hexescape(ch)

    if args.quote_char == c:
        return "\\" + c
    if c == '\\':
        return '\\\\'

    if c in standard_escapes:
        return standard_escapes[c]

    if 32 <= ch <= 126:
        return c
    else:
        return hexescape(ch)

def encode_generic(s, args, width_overhead):
    k = args.input_width
    if k is None:
        k = len(s)
    lines = []
    for i in xrange(0, len(s), k):
        inpos = i
        inend = i+k
        while inpos < inend:
            prevhex = False
            line = []
            linesz = 0
            while inpos < inend:
                nextout = encode_char(s[inpos], args, not (args.style == 'c' and prevhex))
                if args.output_width is not None and\
                  (line and len(nextout) + linesz > args.output_width - width_overhead):
                    break
                inpos += 1
                line.append(nextout)
                linesz += len(nextout)
                prevhex = nextout.startswith('\\x')
            lines.append(''.join(line))
    return lines

def encode_c(s, args):
    if args.quote_char is None:
        args.quote_char = '"'

    return '\n'.join('%c%s%c' % (args.quote_char, line, args.quote_char) for line in encode_generic(s, args, 3))

def encode_echo(s, args):
    if args.quote_char is None:
        args.quote_char = "'"

    return '\n'.join('echo -ne %c%s%c' % (args.quote_char, line, args.quote_char) for line in encode_generic(s, args, 12))

def encode_bash(s, args):
    if args.quote_char is None:
        args.quote_char = "'"

    return '\n'.join('$%c%s%c' % (args.quote_char, line, args.quote_char) for line in encode_generic(s, args, 4))

def encode_python(s, args):
    if args.quote_char is None:
        args.quote_char = '"'

    return '\\\n'.join('%c%s%c' % (args.quote_char, line, args.quote_char) for line in encode_generic(s, args, 4))

def parse_args(argv):
    parser = argparse.ArgumentParser('Encode a file as a backslash-escaped string.')
    parser.add_argument('-x', '--no-printable', action='store_true', help="Use escapes only, no printable characters.")
    parser.add_argument('-w', '--input-width', type=int, metavar='WIDTH', help="Break input into WIDTH-sized chunks")
    parser.add_argument('-W', '--output-width', type=int, metavar='WIDTH', help="Generate chunks of no more than WIDTH bytes long")
    parser.add_argument('--style', choices=('c', 'echo', 'bash', 'python'), default='python', help="Output style: C string, echo commands, Bash literal string or Python/JS string")
    parser.add_argument('-b', dest='style', action='store_const', help="Bash literals output, e.g. $'...'", const='bash')
    parser.add_argument('-c', dest='style', action='store_const', help="C string output", const='c')
    parser.add_argument('-e', dest='style', action='store_const', help="echo -e output", const='echo')
    parser.add_argument('--quote-char', choices=("'", '"'), help="Quote character: single or double quote (default: double for c, single for others)")
    parser.add_argument('-\'', dest='quote_char', action='store_const', help="Use single quotes", const="'")
    parser.add_argument('-"', dest='quote_char', action='store_const', help="Use double quotes", const='"')
    parser.add_argument('file', nargs='?', help="Input file; if not specified, read from stdin.")
    return parser.parse_args(argv)

def main(argv):
    args = parse_args(argv)

    if args.file:
        f = open(args.file, 'rb')
    else:
        f = sys.stdin

    sys.stdout.write(globals()['encode_' + args.style](f.read(), args))

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv[1:]))
