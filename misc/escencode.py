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
    per_line_quotes = False, # are quote chars required on every line?

    standard_escapes = make_escape_dict('abfnrtv\\'), # standard short escape characters
    hex_escape = True, # allow hex escapes?
    oct_escape = True, # allow octal escapes (backslash plus 1-3 octal digits)?
    oct_leading_zero = False, # do octal escapes require leading zero?
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

# Remember, we want to avoid implicit newlines. Thus, multiline strings (!per_line_quotes)
# are only allowed if they will not insert newlines on each line.
default_dialect = Dialect()
python_dialect = Dialect(quote_char="'", line_continuation='\\')
c_dialect = Dialect(hex_continues=True, line_continuation='\\', force_encode='?') # force encode ? to avoid trigraphs
ruby_dialect = Dialect(quote_char='"', line_continuation='\\', standard_escapes=make_escape_dict('bfnrt\\#'))
echo_dialect = Dialect(quote_char="'", per_line_quotes=True, line_prefix="echo -ne ", force_encode="'", oct_leading_zero=True)
js_dialect = Dialect(quote_char="'", oct_escape=False, standard_escapes=make_escape_dict('bfnrt\\')) # JS is deprecating octal escapes
java_dialect = Dialect(quote_char='"', per_line_quotes=True, line_continuation='+', hex_escape=False, standard_escapes=make_escape_dict('bfnrt\\')) # Java doesn't have hex escapes at all!
allhex_dialect = Dialect(quote_char='"', per_line_quotes=True, line_continuation='', hex_escape=True, oct_escape=False, standard_escapes={}, force_encode="".join(map(chr, range(256))))

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
                val = '%03o' % ord(c)
            else:
                val = '%o' % ord(c)
            if self.dialect.oct_leading_zero and (not val.startswith('0') or len(val) == 3):
                val = '0' + val
            return '\\' + val
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
    first = True

    while 1:
        line = [dialect.line_prefix]
        if first or dialect.per_line_quotes:
            line.append(dialect.quote_char)
        first = False
        line_size = len(''.join(line)) + len(dialect.line_suffix)
        if dialect.per_line_quotes:
            line_size += len(dialect.quote_char) + len(dialect.line_continuation)
        else:
            line_size += max(len(dialect.quote_char), len(dialect.line_continuation))

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
        if c:
            if dialect.per_line_quotes:
                line.append(dialect.quote_char)
            line.append(dialect.line_suffix)
            line.append(dialect.line_continuation)
        else:
            line.append(dialect.quote_char)
            line.append(dialect.line_suffix)
        yield ''.join(line)
        if not c:
            break

def java_join(chunks):
    ''' Join chunks recursively in a binary tree style. '''
    if len(chunks) <= 3:
        return '+new String()+'.join('(\n%s\n)' % c for c in chunks)

    mid = len(chunks)//2
    return '(%s)+new String()+(%s)' % (java_join(chunks[:mid]), java_join(chunks[mid:]))

def encode_java(s, input_width=None, line_width=None):
    ''' Java strings are limited to about 64K, which means that we have to split the input
    into multiple large chunks..
    Java's compiler will stack overflow if we do too many `+` operations in a row, so we
    have to join the chunks in a binary-tree style to avoid nesting too deeply.
    tl;dr: Java sucks. '''
    import cStringIO

    chunksize = 32767 # UTF-8 representation may make the string up to 65534 bytes in size

    lines = []
    for i in xrange(0, len(s), chunksize):
        chunk = cStringIO.StringIO(s[i:i+chunksize])
        chunk_str = '\n'.join(encode_file(chunk, java_dialect, input_width, line_width))
        lines.append(chunk_str)
    return java_join(lines)

def parse_args(argv):
    parser = argparse.ArgumentParser('Encode a file as a backslash-escaped string.')
    parser.add_argument('-w', '--input-width', type=int, metavar='WIDTH', help="Encode no more than WIDTH bytes in each line")
    parser.add_argument('-W', '--output-width', type=int, metavar='WIDTH', help="Limit output lines to no more than WIDTH characters")
    parser.add_argument('-s', '--style', choices=('c', 'echo', 'python', 'js', 'java', 'ruby', 'allhex'), default='python', help="Output style/language")
    parser.add_argument('file', nargs='?', help="Input file; if not specified, read from stdin.")
    return parser.parse_args(argv)

def main(argv):
    args = parse_args(argv)

    if args.file:
        f = open(args.file, 'rb')
    else:
        f = sys.stdin

    if args.style == 'java':
        # special-case java due to Java language/compiler limitations
        print encode_java(f.read(), args.input_width, args.output_width)
        return

    dialect = Dialect(globals()[args.style + '_dialect'])
    for line in encode_file(f, dialect, args.input_width, args.output_width):
        print line

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv[1:]))
