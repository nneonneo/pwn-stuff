''' Test cases for rxpwn. Python 2 & 3 compatible. '''
from __future__ import print_function

import unittest

import rxpwn
from rxpwn import rd, wr, pr, interactive

import random
import re
import threading
import sys
import socket

_PY3 = sys.version_info >= (3,)
if _PY3:
    _bytes_to_text = lambda s: s.decode('latin1')
else:
    _bytes_to_text = lambda s: s

def mkpipefiles():
    import os
    r, w = os.pipe()

    rf = os.fdopen(r, 'r', 1)
    wf = os.fdopen(w, 'w', 1)
    return rf, wf

def strip_ansi(s):
    return re.sub(r'\x1b\[[\d,]*m', '', s)

def tryclose(s):
    try:
        s.close()
    except Exception:
        pass

class OutputCapturingTestCase(unittest.TestCase):
    def setUp(self):
        # capture stdin, stdout
        self._oldin = sys.stdin
        self._oldout = sys.stdout

        sys.stdin, self.stdin = mkpipefiles()
        self.stdout, sys.stdout = mkpipefiles()
        # set nonblocking stdout read
        import os, fcntl
        fcntl.fcntl(self.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)

    def tearDown(self):
        # revert stdin, stdout
        tryclose(self.stdin)
        tryclose(sys.stdin)
        tryclose(self.stdout)
        tryclose(sys.stdout)
        sys.stdin = self._oldin
        sys.stdout = self._oldout

class TestRXPwnSockets(OutputCapturingTestCase):
    def setUp(self):
        # setup server socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for retry in range(100):
            try:
                host, port = 'localhost', random.randrange(1024, 65534)
                s.bind((host, port))
            except socket.error:
                continue
            break

        s.listen(1)
        self._server_socket = s
        
        # setup client socket
        self.sock = rxpwn.Socket((host, port))

        # accept client
        self.server, address = self._server_socket.accept()

        OutputCapturingTestCase.setUp(self)

    def tearDown(self):
        OutputCapturingTestCase.tearDown(self)

        # close client socket
        tryclose(self.sock)

        # close server socket
        tryclose(self.server)
        tryclose(self._server_socket)


    def test_rd_output_echo_escape(self):
        instr = b'\x00 \t\nabc123\x80\xff'
        self.server.send(instr)
        res = self.sock.rd(len(instr))
        output = strip_ansi(self.stdout.read())

        self.assertEqual(res, instr)
        self.assertEqual(output, '\\x00 \\x09\nabc123\\x80\\xff')

    def test_rd_output_noecho(self):
        self.sock.echo = False

        instr = b'\x00 \t\nabc123\x80\xff'
        self.server.send(instr)
        res = self.sock.rd(len(instr))

        # ensure stdout isn't empty (since self.stdout is nonblocking)
        sys.stdout.write('x')
        sys.stdout.flush()

        output = self.stdout.read()

        self.assertEqual(res, instr)
        # check that there was no output besides the character we stuffed in
        self.assertEqual(output, 'x')

    def test_rd_output_echo_noescape(self):
        self.sock.escape = False

        instr = b'\x00 \t\nabc123\x80\xff'
        self.server.send(instr)
        res = rd(len(instr))
        output = self.stdout.read()

        self.assertEqual(res, instr)
        self.assertEqual(output, _bytes_to_text(instr))

    def test_rd_suffix_int(self):
        self.server.send(b'abcdefghi')
        self.assertEqual(rd(3), b'abc')
        self.assertEqual(rd(4), b'defg')

    def test_rd_suffix_bytes(self):
        self.server.send(b'abcdefghi')
        self.assertEqual(rd(b'c'), b'abc')
        self.assertEqual(rd(b'ef'), b'def')
        self.assertEqual(rd(bytearray(b'i')), b'ghi')

    def test_rd_suffix_re(self):
        self.server.send(b'abcdefghi')
        self.assertEqual(rd(re.compile(b'[cd]')), b'abc')
        self.assertEqual(rd(re.compile(b'.')), b'd')
        self.assertEqual(rd(re.compile(b'i')), b'efghi')

    def test_rd_suffix_mixed(self):
        self.server.send(b'abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(rd(b'c', b'e'), b'abc')
        self.assertEqual(rd(b'i', b'e'), b'de')
        self.assertEqual(rd(b'jq', b'gh'), b'fgh')
        self.assertEqual(rd(5, b'k'), b'ijk')
        self.assertEqual(rd(5, b'u'), b'lmnop')
        self.assertEqual(rd(3, 1), b'q')
        self.assertEqual(rd(99, re.compile(b's')), b'rs')
        self.assertEqual(rd(1, b'tu', re.compile(b'uv')), b't')
        self.assertEqual(rd(3, b'v', re.compile(b'y')), b'uv')
        self.assertEqual(rd(5, b'z', re.compile(b'x')), b'wx')


    def test_wr_output_echo(self):
        instr = b'\x00 \t\nabc123\x80\xff'

        wr(instr)
        res = self.server.recv(len(instr))
        output = strip_ansi(self.stdout.read())

        self.assertEqual(instr, res)
        self.assertEqual(output, '\\x00 \\x09\nabc123\\x80\\xff')

    def test_wr_output_noecho(self):
        self.sock.echo = False

        instr = b'\x00 \t\nabc123\x80\xff'
        wr(instr)
        res = self.server.recv(len(instr))

        # ensure stdout isn't empty (since self.stdout is nonblocking)
        sys.stdout.write('x')
        sys.stdout.flush()

        output = self.stdout.read()

        self.assertEqual(res, instr)
        # check that there was no output besides the character we stuffed in
        self.assertEqual(output, 'x')

    def test_wr_output_echo_noescape(self):
        self.sock.escape = False

        instr = b'\x00 \t\nabc123\x80\xff'
        wr(instr)
        res = self.server.recv(len(instr))
        output = strip_ansi(self.stdout.read())

        self.assertEqual(res, instr)
        self.assertEqual(output, _bytes_to_text(instr))

    def assertServerRecv(self, s):
        self.assertEqual(self.server.recv(len(s)), s)

    def test_wr_types(self):
        wr(b'1234')
        self.assertServerRecv(b'1234')

        wr(bytearray(b'1234'))
        self.assertServerRecv(b'1234')

        wr(1234)
        self.assertServerRecv(b'1234')

        wr("1234")
        self.assertServerRecv(b'1234')

        wr((1,))
        self.assertServerRecv(b'(1,)')

    def test_pr_types(self):
        pr(b'1234')
        self.assertServerRecv(b'1234\n')

        pr(bytearray(b'1234'))
        self.assertServerRecv(b'1234\n')

        pr(1234)
        self.assertServerRecv(b'1234\n')

        pr("1234")
        self.assertServerRecv(b'1234\n')

        pr((1,))
        self.assertServerRecv(b'(1,)\n')

    def test_pr_multiple(self):
        pr(1, b'asd', 'hi')
        self.assertServerRecv(b'1 asd hi\n')

    def test_interactive_stdin_close(self):
        ok = [False]
        def _interactive_thread():
            interactive()
            ok[0] = True

        thread = threading.Thread(target=_interactive_thread)
        thread.start()
        self.stdin.close()
        thread.join()
        self.assertEqual(ok[0], True)
        self.assertEqual(strip_ansi(self.stdout.read()), 
            '*** Entering interactive mode ***\n'
            '*** Exiting interactive mode ***\n')

    def test_interactive_server_close(self):
        ok = [False]
        def _interactive_thread():
            interactive()
            ok[0] = True

        thread = threading.Thread(target=_interactive_thread)
        thread.start()
        self.server.close()
        thread.join()
        self.assertEqual(ok[0], True)
        self.assertEqual(strip_ansi(self.stdout.read()), 
            '*** Entering interactive mode ***\n'
            '*** Connection closed by remote host ***\n')

    def test_interactive_basic(self):
        ok = [False]
        def _interactive_thread():
            interactive()
            ok[0] = True

        thread = threading.Thread(target=_interactive_thread)
        thread.start()

        self.stdin.write('abcd\n')
        res = self.server.recv(5)
        self.assertEqual(res, b'abcd\n')

        self.server.send(res.upper())

        self.stdin.close()
        thread.join()
        self.assertEqual(ok[0], True)
        self.assertEqual(strip_ansi(self.stdout.read()), 
            '*** Entering interactive mode ***\n'
            'ABCD\n'
            '*** Exiting interactive mode ***\n')

    def test_rd_partial(self):
        self.server.send(b'test')
        self.server.shutdown(socket.SHUT_WR)
        with self.assertRaises(rxpwn.PartialReadError) as ecm:
            rd(b'\n')
        self.assertEqual(ecm.exception.data, b'test')

    def test_rd_oserror(self):
        self.sock.sock.setblocking(0)
        self.server.send(b'test')
        with self.assertRaises(rxpwn.PartialReadError) as ecm:
            rd(b'\n')
        self.assertEqual(ecm.exception.data, b'test')

class TestRXPwnMisc(OutputCapturingTestCase):
    def test_pause(self):
        self.stdin.write('\n')
        rxpwn.pause()
        self.assertEqual(strip_ansi(self.stdout.read()), 'Pausing...')

    def test_log(self):
        ''' validate that log behaves like print() '''
        rxpwn.log(b'abcd', 'abcd')
        print(b'abcd', 'abcd')
        l1 = strip_ansi(self.stdout.readline())
        l2 = '[+] ' + self.stdout.readline()
        self.assertEqual(l1, l2)

    def test_err(self):
        ''' validate that err behaves like print() '''
        rxpwn.err(b'abcd', 'abcd')
        print(b'abcd', 'abcd')
        l1 = strip_ansi(self.stdout.readline())
        l2 = '[-] ' + self.stdout.readline()
        self.assertEqual(l1, l2)

class TestRXPwnPackUnpack(unittest.TestCase):
    def test_pack(self):
        self.assertEqual(rxpwn.plQ(0x4142434445464748), b'HGFEDCBA')
        self.assertEqual(rxpwn.pQ(0x4142434445464748), b'HGFEDCBA')
        self.assertEqual(rxpwn.pbQ(0x4142434445464748), b'ABCDEFGH')

    def test_unpack(self):
        self.assertEqual(rxpwn.ubQ(b'ABCDEFGH'), 0x4142434445464748)
        self.assertEqual(rxpwn.ulQ(b'HGFEDCBA'), 0x4142434445464748)
        self.assertEqual(rxpwn.uQ(b'HGFEDCBA'), 0x4142434445464748)
        self.assertEqual(rxpwn.ubI(b'ABCDEFGH'), (0x41424344, 0x45464748))

if __name__ == '__main__':
    unittest.main()
