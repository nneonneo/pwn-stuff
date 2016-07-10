''' Robert Xiao (@nneonneo)'s pwning library.

This library focuses on brevity and easy-to-remember shortcuts.
The function names are deliberately very short to make them easy
to type and so they don't take up too much of your script - you'll
probably use these a lot.

Socket: create a socket to a remote host
- All methods of Socket are also available as globals which operate on the last opened socket
- rd: read a set number of bytes, or read until a suffix is found, or until the input matches a regex
- pr: print stuff to the socket (adds a newline, works just like print())
- wr: write something to the socket (single item, no newline)
- interactive: enter an interactive loop like nc or telnet (Ctrl+D to quit the interactive loop and resume your script)

Logging methods
- pause(): pause script execution (useful to give you time to attach a debugger, for example)
- log: print a log message, like print() but with color
- err: print an error message, like print() but with color

Binary conversion:
- uX: unpack using format code X in little-endian format
    X is in 'bBhHiIqQfd' (usual struct codes: byte, short, int, long long, float, double and their unsigned variants)
    Pass in a string of unit length (e.g. 8 bytes for Q) and get a single value out.
    Pass in a longer string and get a list of values (e.g. 16 bytes to get two longs out)
    (Yes, this is slightly inconsistent behaviour, but it's really convenient.)
- pX: pack using format code X in little-endian
    You can pass in multiple arguments and their packed values will just be concatenated. (e.g pQ(1, 2) to get a 16-byte string)
- ulX, plX: synonyms for uX, pX (l = little endian)
- unX, pnX: like uX, pX but use host endian
- ubX, pbX: like uX, pX but use big-endian
'''

from __future__ import print_function

from struct import calcsize, pack, unpack
import socket
import sys
import re
import os
from contextlib import contextmanager

import string
_printable_bytes = {ord(c.encode()) for c in string.printable if (not c.isspace() or c in ' \n')}

_PY3 = sys.version_info >= (3,)

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

_ANSI_COLOR_RED = '\x1b[31m'
_ANSI_COLOR_GREEN = '\x1b[32m'
_ANSI_COLOR_YELLOW = '\x1b[33m'
_ANSI_COLOR_DEFAULT = '\x1b[39m'
_ANSI_UNDERLINE_ON = '\x1b[4m'
_ANSI_UNDERLINE_OFF = '\x1b[24m'

@contextmanager
def _ansi_color(color):
    sys.stdout.write(color)
    yield
    sys.stdout.write(_ANSI_COLOR_DEFAULT)

@contextmanager
def _ansi_underline():
    sys.stdout.write(_ANSI_UNDERLINE_ON)
    yield
    sys.stdout.write(_ANSI_UNDERLINE_OFF)

## Useful globals
RE = re.compile

class PartialReadError(IOError):
    def __init__(self, data, exc):
        IOError.__init__(self, getattr(exc, 'errno', None), getattr(exc, 'strerror', None))
        self.args = (data, exc)
        self.data = data
        self.__cause__ = exc

    def __str__(self):
        causestr = str(self.__cause__)
        if causestr:
            causestr = ": " + causestr
        return '%r (%s%s)' % (self.data, type(self.__cause__).__name__, causestr)
    def __repr__(self):
        return '%s%r' % (type(self).__name__, self.args)

## Socket stuff
class Socket:
    ''' Basic socket class for interacting with remote services. '''

    echo = True # global echo option, can be set to affect all future sockets
    escape = os.isatty(1) # global escape option
    _last_socket = None # most recent socket, for global rd/pr/wr functions

    # echo => whether rd/pr/wr echo back what they write
    # escape => whether rd/pr/wr escape unprintables
    def __init__(self, target, echo=None, escape=None):
        ''' Create a new socket connected to the target. '''
        Socket._last_socket = self
        if isinstance(target, (tuple, str)):
            self.sock = socket.create_connection(target)
        else:
            self.sock = target # assume socket object

        if echo is None:
            echo = Socket.echo
        self.echo = echo

        if escape is None:
            escape = Socket.escape
        self.escape = escape

    def _print_fmt(self, x):
        ''' Write a bytestring to the terminal, escaping non-printable characters. '''
        for c in bytearray(x):
            if not self.escape or c in _printable_bytes:
                sys.stdout.write(chr(c))
            else:
                # underline this text
                with _ansi_underline():
                    sys.stdout.write('\\x%02x' % c)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        self.sock.close()

    # Compatibility functions for regular sockets
    def shutdown(self, how):
        self.sock.shutdown(how)

    def fileno(self):
        return self.sock.fileno()

    def recv(self, n):
        return self.rd(n)

    def send(self, x):
        return self.wr(x)

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
            try:
                x = self.sock.recv(1)
            except socket.error as e:
                raise PartialReadError(bytes(out), e)
            if not x:
                raise PartialReadError(bytes(out), EOFError())
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
            with _ansi_color(_ANSI_COLOR_GREEN):
                self._print_fmt(s)
            sys.stdout.flush()

    def pr(self, *bits, **kwargs):
        ''' Print something to the socket. Like Python 3's print() function. Adds a newline. '''
        bits = map(_byteize, bits)
        self.wr(b' '.join(bits) + b'\n', **kwargs)

    def interactive(self):
        ''' Go interactive, allowing the terminal user to interact directly with the service. Like nc. '''
        import select

        with _ansi_color(_ANSI_COLOR_RED):
            print("*** Entering interactive mode ***")
        stdin_fd = sys.stdin.fileno()
        sock_fd = self.sock.fileno()
        while 1:
            r,w,x = select.select([stdin_fd, sock_fd], [], [])

            if sock_fd in r:
                res = self.sock.recv(4096)
                if not res:
                    with _ansi_color(_ANSI_COLOR_RED):
                        print("*** Connection closed by remote host ***")
                    break
                self._print_fmt(res)
                sys.stdout.flush()

            if stdin_fd in r:
                res = sys.stdin.readline()
                if not res:
                    with _ansi_color(_ANSI_COLOR_RED):
                        print("*** Exiting interactive mode ***")
                    break
                self.sock.send(_byteize(res))

def SSLSocket(addr, *args, **kwargs):
    from ssl import wrap_socket
    return Socket(wrap_socket(socket.create_connection(addr)), *args, **kwargs)

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
    with _ansi_color(_ANSI_COLOR_RED):
        _str_input("Pausing...")

def log(*args, **kwargs):
    with _ansi_color(_ANSI_COLOR_YELLOW):
        print('[+]', end=' ')
        print(*args, end='', **kwargs)
    print()

def err(*args, **kwargs):
    with _ansi_color(_ANSI_COLOR_RED):
        print('[-]', end=' ')
        print(*args, end='', **kwargs)
    print()

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
        res = unpack(endian + str(len(data)//sz) + ch, data)
        if len(res) == 1:
            # fix annoying behaviour of unpack
            return res[0]
        return res
    unpacker.__name__ = name
    return unpacker

def _init_pack_funcs():
    for ch in 'bBhHiIqQfd':
        for endian, endianch in [('<',''), ('<','l'), ('>','b'), ('@','n')]:
            name = endianch + ch
            globals()['p' + name] = _genpack('p' + name, endian, ch)
            globals()['u' + name] = _genunpack('u' + name, endian, ch)

_init_pack_funcs()
