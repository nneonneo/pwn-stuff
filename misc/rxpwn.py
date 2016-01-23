''' Robert Xiao (@nneonneo)'s pwning library. Very basic. '''
from __future__ import print_function

from socket import *
from struct import *
import sys
import re

import string
_printable_bytes = {ord(c.encode()) for c in string.printable if (not c.isspace() or c in ' \n')}

_PY3 = sys.version_info >= (3,)

def _stringize(x):
    try:
        return str(x)
    except Exception:
        return repr(x)

def _byteize(x):
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    return str(x).encode('latin1')

if _PY3:
    _str_input = input
    _int_types = (int,)
else:
    _str_input = raw_input
    _int_types = (int, long)

_re_pattern_type = type(re.compile(b''))

## Socket stuff
class Socket:
    ''' Basic socket class for interacting with remote services. '''

    echo = True # global echo option, can be set to affect all future sockets
    escape = True # global escape option
    _last_socket = None # most recent socket, for global rd/pr/wr functions

    # echo => whether rd/pr/wr echo back what they write
    # escape => whether rd/pr/wr escape unprintables
    def __init__(self, target):
        ''' Create a new socket connected to the target. '''
        Socket._last_socket = self
        self.sock = socket()
        self.sock.connect(target)
        self.echo = Socket.echo
        self.escape = Socket.escape

    def _print_fmt(self, x):
        ''' Write a bytestring to the terminal, escaping non-printable characters. '''
        for c in bytearray(x):
            if not self.escape or c in _printable_bytes:
                sys.stdout.write(chr(c))
            else:
                # underline this text
                sys.stdout.write('\x1b[4m\\x%02x\x1b[24m' % c)

    def rd(self, *suffixes, **kwargs):
        ''' Read until a particular set of criteria come true.

        Criteria can be:
            - integers to read a specified # of bytes,
            - strings to read until a particular suffix is found, or
            - compiled regexes to read until the buffer satisfies the
              regex with .search.

        rd returns when any criteria is fulfilled. '''

        out = bytearray()
        echo = kwargs.get('echo', self.echo)
        while 1:
            x = self.sock.recv(1)
            if not x:
                raise EOFError()
            if echo:
                self._print_fmt(x)
                sys.stdout.flush()
            out += x

            for suffix in suffixes:
                if isinstance(suffix, _int_types):
                    if len(out) == suffix:
                        break
                elif isinstance(suffix, (bytes, bytearray)):
                    if out.endswith(suffix):
                        break
                elif isinstance(suffix, _re_pattern_type):
                    if suffix.search(out):
                        break
                else:
                    raise ValueError("can't understand suffix %r" % suffix)
            else:
                continue
            break
        return bytes(out)

    def wr(self, s, **kwargs):
        ''' Write something to the socket. No newline is added. '''
        echo = kwargs.get('echo', self.echo)
        s = _byteize(s)
        self.sock.send(s)
        if echo:
            # colorize sent data green
            sys.stdout.write('\x1b[32m')
            self._print_fmt(s)
            sys.stdout.write('\x1b[39m')
            sys.stdout.flush()

    def pr(self, *bits, **kwargs):
        ''' Print something to the socket. Like Python 3's print() function. Adds a newline. '''
        bits = map(_byteize, bits)
        self.wr(b' '.join(bits) + b'\n', **kwargs)

    def interactive(self):
        ''' Go interactive, allowing the terminal user to interact directly with the service. Like nc. '''
        import select

        print("\x1b[31m*** Entering interactive mode ***\x1b[39m")
        stdin_fd = sys.stdin.fileno()
        sock_fd = self.sock.fileno()
        while 1:
            r,w,x = select.select([stdin_fd, sock_fd], [], [])
            if sock_fd in r:
                res = self.sock.recv(4096)
                if not res:
                    print("\x1b[31m*** Connection closed by remote host ***\x1b[39m")
                    break
                self._print_fmt(res)
                sys.stdout.flush()
            if stdin_fd in r:
                res = sys.stdin.readline()
                if not res:
                    raise EOFError()
                self.sock.send(_byteize(res))

def rd(*args, **kwargs):
    return Socket._last_socket.rd(*args, **kwargs)

def pr(*args, **kwargs):
    return Socket._last_socket.pr(*args, **kwargs)

def wr(*args, **kwargs):
    return Socket._last_socket.wr(*args, **kwargs)

def interactive(*args, **kwargs):
    return Socket._last_socket.interactive(*args, **kwargs)

## Misc
def pause():
    _str_input("\x1b[31mPausing...\x1b[39m")

def log(*args):
    print('\x1b[33m' + ' '.join(map(str, args)) + '\x1b[39m')

def err(*args):
    print('\x1b[31m' + ' '.join(map(str, args)) + '\x1b[39m')

## Pack/unpack
def _genpack(name, endian, ch):
    def packer(*args):
        return pack(endian + str(len(args)) + ch, *args)
    packer.__name__ = name
    return packer

def _genunpack(name, endian, ch):
    sz = calcsize(ch)
    def unpacker(data):
        if len(data) % sz != 0:
            raise ValueError("buffer size is not a multiple of %d" % sz)
        res = unpack(endian + str(len(data)/sz) + ch, data)
        if len(res) == 1:
            # fix annoying behaviour of unpack
            return res[0]
        return res
    unpacker.__name__ = name
    return unpacker

for ch in 'bBhHiIqQfd':
    for endian, endianch in [('',''), ('<','l'), ('>','b')]:
        name = endianch + ch
        globals()['p' + name] = _genpack('p' + name, endian, ch)
        globals()['u' + name] = _genunpack('u' + name, endian, ch)
