# Super CRT: handle non-pairwise-coprime inputs

def gcd(a, b):
    while b:      
        a, b = b, a % b
    return a

def egcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0

def modinv(a, n):
    g, x, _ = egcd(a, n)
    if g == 1:
        return x % n
    else:
        raise ValueError("%d is not invertible mod %d" % (a, n))

def solve_crt(rems, mods):
    ''' Solve a system of modular equivalences via the Chinese Remainder Theorem.

    Does not require pairwise coprime moduli. '''

    # copy inputs
    orems, omods = rems, mods
    rems = list(rems)
    mods = list(mods)

    newrems = []
    newmods = []

    for i in range(len(mods)):
        for j in range(i+1, len(mods)):
            g = gcd(mods[i], mods[j])
            if g == 1:
                continue
            if rems[i] % g != rems[j] % g:
                raise ValueError("inconsistent remainders at positions %d and %d (mod %d)" % (i, j, g))
            mods[j] //= g

            while 1:
                # transfer any remaining gcds to mods[j]
                g = gcd(mods[i], mods[j])
                if g == 1:
                    break
                mods[i] //= g
                mods[j] *= g

        if mods[i] == 1:
            continue

        newrems.append(rems[i] % mods[i])
        newmods.append(mods[i])

    rems, mods = newrems, newmods

    # standard CRT
    s = 0
    n = 1
    for k in mods:
        n *= k

    for i in range(len(mods)):
        ni = n // mods[i]
        s += rems[i] * modinv(ni, mods[i]) * ni
    return s % n, n

if __name__ == '__main__':
    assert solve_crt([22%15, 22%21, 22%35], [15,21,35]) == (22, 105)
    assert solve_crt([22%10, 22%8], [10, 8]) == (22, 40)
