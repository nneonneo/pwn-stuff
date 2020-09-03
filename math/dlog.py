from Crypto.Util import number
from functools import reduce

def isqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

class FastDlog(object):
    def __init__(self, g, maxe, p):
        lookup = {}

        a = isqrt(maxe)+1

        s = 1
        ga = pow(g, a, p)
        for j in range(a):
            if (j+1) % 100000 == 0: print('cache progress...', j)
            lookup[s] = j
            s = (ga*s) % p

        self.lookup = lookup
        self.max = a
        self.g = g
        self.p = p

    def dlog(self, y):
        ''' Compute x s.t. g^x === y mod p using baby step-giant step.
    
        maxe is a bound on the maximum exponent to test (for unrestricted
        logarithms, set maxe = p-1).

        Running time is proportional to sqrt(maxe). '''

        lookup = self.lookup
        a = self.max
        p = self.p
        g = self.g
        s = 1
        for i in range(a):
            if (i+1) % 100000 == 0: print('lookup progress...', i)
            v = (y*s) % p
            if v in lookup:
                return lookup[v] * a - i
            s = (g*s) % p

def chinese_remainder(n, a):
    ''' Compute a number from its moduluses.

    From Rosetta Code. '''

    sum = 0
    prod = reduce(lambda a, b: a*b, n)
 
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * number.inverse(p, n_i) * p
    return sum % prod

def pohlig_hellman(g, y, p, factors):
    ''' Compute x s.t. g^x === y mod p. Decomposes problem using factors of ord_p(g).

    g: generator
    y: number to be logarithmed
    p: prime (or prime power) modulus
    factors: a list of [(factor, multiplicity)] factors of ord_p(g)

    This function works fastest when ord_p(g) is smooth (i.e. when
    it has only small prime factors).

    Calculating the value and factorization of ord_p(g) is left as an
    exercise to the reader.

    Running time is essentially proportional to the square-root of
    `max(q for q,r in factors)`.
    '''

    order = 1
    for f, m in factors:
        order *= f ** m

    xi = []
    ni = []
    for f, m in factors:
        xf = 0
        cury = y
        qtot = f ** m
        base = pow(g, order // f, p)
        dlog = FastDlog(base, f+1, p)
        for k in range(m):
            q = f ** (k+1)
            lhs = pow(cury, order // q, p)
            if base == 1:
                if lhs != 1:
                    raise Exception("no solution")
                else:
                    continue

            exp = (dlog.dlog(lhs) % f) * (f ** k)
            xf += exp
            if k != m-1:
                cury *= number.inverse(pow(g, exp, p), p)
        xi.append(xf)
        ni.append(qtot)

    return chinese_remainder(ni, xi)

def run_tests():
    if 1:
        # Test prime power modulus
        a = 2
        n = 729
        for i in range(n):
            y = pow(a, i, n)
            x = pohlig_hellman(a, y, n, [(2, 1), (3, 5)])
            assert pow(a, x, n) == y

    if 1:
        # Test factor multiplicity
        p = 8101
        a = 6
        assert pohlig_hellman(a, 7531, p, [(2,2), (3,4), (5,2)]) == 6689

    if 1:
        # Test larger primes (poooooooow from HITCON 2015)
        p = 195589859419604305972182309315916027436941011486827038011731627454673222943892428912238183097741291556130905026403820602489277325267966860236965344971798765628107804393049178848883490619438682809554522593445569865108465536075671326806730534242861732627383004696136244305728794347161769919436748766859796527723
        q = 4759647095086827597559114855685975263112106458932414012998147177848303887783492510354911068366203455488902018600593880874117783509946030773587965941

        # p-1 factors as q * 2 * (3**336)
        b = pow(7, q, p)
        # b has order 2*3^336

        assert pohlig_hellman(b, pow(b, 133713371337, p), p, [(2, 1), (3, 336)]) == 133713371337

    if 1:
        # sanity tests
        assert FastDlog(6, 60, 61).dlog(pow(6, 38, 61)) == 38
        for i in range(60):
            assert pohlig_hellman(6, pow(6, i, 61), 61, [(2,2),(3,1),(5,1)]) == i

    if 1:
        # More tests (alicegame from MMACTF 2015)
        p = 2488665134832285853092948293008213155978176626596688076035471
        g = 2059715652525439319626604918085000816657307363269561921215002
        h = 2446745500193945956354541994529416399024970775365943146442167
        og = 1244332567416142926546474146504106577989088313298344038017735
        factors = [(2, 1), (3, 4), (5, 1), (13, 1), (397, 1), (34703, 1), (142231, 1), (663997, 1), (1335134757001, 1), (1681985613731, 1), (80885896977317, 1)]

        print(pohlig_hellman(g, h, p, factors))
        # => 398107572758509184512000160060709442427941395118355047140976

if __name__ == '__main__':
    run_tests()
