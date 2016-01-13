#!/usr/bin/env python
import sys
import argparse

def make_escape_dict(s):
    known = {'a':'\a', 'b':'\b', 'f':'\f', 'n':'\n', 'r':'\r', 't':'\t', 'v':'\v'}
    return {known.get(c, c): '\\'+c for c in s}

dialect_defaults = dict(
    quote_char = '"', # quote character
    line_continuation = '', # string to append at the end of non-final lines
    line_prefix = '', # string to prepend to every line
    line_suffix = '', # string to append to every line

    standard_escapes = make_escape_dict('abfnrtv\\'), # standard short escape characters
    hex_escape = True, # allow hex escapes?
    oct_escape = True, # allow octal escapes (backslash plus 1-3 octal digits)?
    hex_continues = False, # are hex escapes unbounded in length?
    force_encode = '', # characters that _must_ be encoded no matter what
)

class Dialect:
    def __init__(self, base=None, **kwargs):
        if base is None:
            for k in dialect_defaults:
                setattr(self, k, dialect_defaults[k])
        else:
            for k in dialect_defaults:
                setattr(self, k, getattr(base, k))

        for k in kwargs:
            if k not in dialect_defaults:
                raise TypeError("unknown dialect key %s" % k)
            setattr(self, k, kwargs[k])

default_dialect = Dialect()
python_dialect = Dialect(quote_char="'", line_continuation='\\')
c_dialect = Dialect(hex_continues=True)
ruby_dialect = Dialect(quote_char='"', line_continuation='\\', standard_escapes=make_escape_dict('bfnrt\\#'))
echo_dialect = Dialect(quote_char="'", line_prefix="echo -ne ", force_encode="'", oct_escape=False)
js_dialect = Dialect(quote_char="'", oct_escape=False, standard_escapes=make_escape_dict('bfnrt\\')) # JS is deprecating octal escapes
java_dialect = Dialect(quote_char='"', line_continuation='+', hex_escape=False, standard_escapes=make_escape_dict('bfnrt\\')) # Java doesn't have hex escapes at all!

class LineEncoder:
    def __init__(self, dialect):
        self.dialect = dialect
        self.prevhex = False # was the previous character encoded as a continuable hex escape? (Only if hex_continues is True)

    def encode(self, c, nextc):
        if c in self.dialect.standard_escapes:
            self.prevhex = False
            return self.dialect.standard_escapes[c]
        if '\x20' <= c <= '\x7e' and c not in self.dialect.force_encode:
            # printable character
            if c == self.dialect.quote_char:
                self.prevhex = False
                return '\\' + c
            if not self.prevhex or c not in '0123456789abcdefABCDEF':
                self.prevhex = False
                return c

        # going to encode the character
        if self.dialect.oct_escape:
            # octal escapes are shorter (or equal length) to hex escapes
            self.prevhex = False
            if nextc and nextc in '01234567':
                return '\\%03o' % ord(c)
            else:
                return '\\%o' % ord(c)
        elif self.dialect.hex_escape:
            self.prevhex = self.dialect.hex_continues
            return '\\x%02x' % ord(c)
        else:
            raise Exception("Cannot encode character %r" % c)

def encode_file(f, dialect, input_width=None, line_width=None):
    input_width = input_width or 1<<63
    line_width = line_width or 1<<63
    c = f.read(1)
    nextc = f.read(1)

    while 1:
        line = [dialect.line_prefix, dialect.quote_char]
        line_size = len(dialect.line_prefix) + len(dialect.quote_char * 2) + len(dialect.line_suffix) + len(dialect.line_continuation)
        input_count = 0
        encoder = LineEncoder(dialect)
        while input_count < input_width and line_size < line_width:
            if not c:
                break
            chunk = encoder.encode(c, nextc)
            if len(chunk) + line_size > line_width:
                break

            line.append(chunk)
            line_size += len(chunk)
            c = nextc
            nextc = f.read(1)
            input_count += 1
        line += [dialect.quote_char, dialect.line_suffix]
        if c:
            line += [dialect.line_continuation]
        yield ''.join(line)
        if not c:
            break

def parse_args(argv):
    parser = argparse.ArgumentParser('Encode a file as a backslash-escaped string.')
    parser.add_argument('-w', '--input-width', type=int, metavar='WIDTH', help="Encode no more than WIDTH bytes in each line")
    parser.add_argument('-W', '--output-width', type=int, metavar='WIDTH', help="Limit output lines to no more than WIDTH characters")
    parser.add_argument('--style', choices=('c', 'echo', 'python', 'js', 'java', 'ruby'), default='python', help="Output style/language")
    parser.add_argument('file', nargs='?', help="Input file; if not specified, read from stdin.")
    return parser.parse_args(argv)

def main(argv):
    args = parse_args(argv)

    if args.file:
        f = open(args.file, 'rb')
    else:
        f = sys.stdin

    dialect = Dialect(globals()[args.style + '_dialect'])
    for line in encode_file(f, dialect, args.input_width, args.output_width):
        print line

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv[1:]))
