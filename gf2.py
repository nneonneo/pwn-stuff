import random
import itertools

def num2vec(x, w):
    return [int(c == '1') for c in '{:0{w}b}'.format(x, w=w)]

def transpose(A):
    return [[A[i][j] for i in xrange(len(A))] for j in xrange(len(A[0]))]

def solve_gf2(A, b):
    ''' Solve a system of linear equations over GF(2), i.e. solve for x where Ax=b.
    Yields *all* solutions.
    
    A: MxN array of bits representing N linear equations over GF(2)
    b: M-element vector of bits

    yields N-element vectors x containing valid solutions to Ax=b
    '''

    # Construct augmented matrix M
    M = [Ar + [bi] for Ar, bi in zip(A, b)]
    nr, nc = len(A), len(A[0])

    # Pack the bits of M into a column of bigints
    M = [sum((long(v) << (nc - i)) for i, v in enumerate(row)) for row in M]

    leads = [-1] * nr
    c = 0
    # gaussian elimination
    for i in xrange(nc):
        mask = 1 << (nc - i)
        for j in xrange(c, nr):
            if M[j] & mask:
                z = M[j]
                M[c], M[j] = M[j], M[c]
                for k in xrange(c+1, nr):
                    if M[k] & mask:
                        M[k] ^= z
                leads[c] = i
                c += 1
                break
        else:
            continue # zeros in this col
        if c >= nr:
            break

    M = [num2vec(row, nc+1) for row in M]
    unset = sorted(set(xrange(nc)) - set(leads))

    # give some randomness to the solution order
    random.shuffle(unset) 
    prod = []
    for i in xrange(len(unset)):
        prod.append(random.choice([[0,1], [1,0]]))

    for possible in itertools.product(*prod):
        x = [-1] * nc
        for i, t in enumerate(unset):
            x[t] = possible[i]
        for i in reversed(xrange(nr)):
            if leads[i] == -1:
                continue
            k = leads[i]
            Mx = sum(Mi * xi for Mi, xi in zip(M[i][k+1:nc], x[k+1:nc]))
            x[k] = (Mx % 2) ^ M[i][nc]
        yield x

if __name__ == '__main__':
    # Example usage showing how to generate arbitrary CRCs
    import os
    from struct import pack, unpack

    target = 0xdeadbeef

    def crc32(x):
        import zlib
        return zlib.crc32(x) & 0xffffffff

    def xorstr(x, y):
        return ''.join([chr(ord(cx) ^ ord(cy)) for cx, cy in zip(x, y)])

    input = []
    crcs = []
    for i in xrange(64):
        v = os.urandom(8)
        input.append(v)
        crcs.append(crc32(v))

    A = transpose([num2vec(c, 32) for c in crcs])
    b = num2vec(target, 32)

    for x in solve_gf2(A, b):
        if sum(x) % 2 == 1:
            # crc32 starts with the constant 0xffffffff, so only odd-parity solutions will be valid
            break
    else:
        raise Exception("no solution!")

    out = '\0' * len(input[0])
    for i, v in enumerate(x):
        if v:
            out = xorstr(out, input[i])

    print out.encode('hex'), hex(crc32(out))
    assert crc32(out) == target
