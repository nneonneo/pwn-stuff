''' Utilities for solving linear and quadratic equations mod n '''

# For fast square roots
from libnum import sqrtmod_prime_power, solve_crt, invmod
import itertools

def solve_linear_mod_2k(a, b, k):
    ''' Calculate solutions to ax+b === 0 mod 2^k '''
    a &= (1<<k) - 1
    b &= (1<<k) - 1
    mp = 0
    while (a & 1) == 0 and (b & 1) == 0 and mp < k:
        a >>= 1
        b >>= 1
        mp += 1
    if (a&1) != (b&1) and mp < k:
        return
    
    basek = k - mp
    basen = 1 << basek
    base = ((-b) * invmod(a, basen)) & (basen - 1)
    for i in range(1 << mp):
        yield base + (i << basek)

def solve_linear_mod_pk(a, b, p, k):
    ''' Calculate solutions to ax+b === 0 mod p^k (where p is an odd prime) '''
    a %= p**k
    b %= p**k
    mp = 0
    while (a % p) == 0 and (b % p) == 0 and mp < k:
        a /= p
        b /= p
        mp += 1
    if (a % p) * (b % p) == 0 and mp < k:
        # Fail: exactly one of a, b is divisible by p
        return

    basek = k - mp
    basen = p ** basek
    base = ((-b) * invmod(a, basen)) % basen
    for i in range(p ** mp):
        yield base + i * basen

def solve_linear_prime_power(a, b, p, k):
    if p == 2:
        return solve_linear_mod_2k(a, b, k)
    else:
        return solve_linear_mod_pk(a, b, p, k)

def solve_linear(a, b, factors):
    gens = []
    if isinstance(factors, dict):
        factors = list(factors.items())

    for p, k in factors:
        gens.append(solve_linear_prime_power(a, b, p, k))

    for solns in itertools.product(*gens):
        yield solve_crt(solns, [p**k for p,k in factors])

def solve_quadratic_mod_2k(a, b, c, k):
    ''' Calculate solutions to axx+bx+c === 0 mod 2^k '''

    a &= (1<<k) - 1
    b &= (1<<k) - 1
    c &= (1<<k) - 1
    mp = 0

    if a == 0:
        # degenerate case
        for soln in solve_linear_mod_2k(b, c, k):
            yield soln
        return

    while (a & 1) == 0 and (b & 1) == 0 and (c & 1) == 0 and mp < k:
        a >>= 1
        b >>= 1
        c >>= 1
        mp += 1

    basek = k - mp
    basen = 1 << basek

    if (a & 1) == 0:
        if (b & 1) == 0:
            # p|a and p|b implies p/|c which is impossible
            return

        # there is a *unique* solution if p|a and p/|b
        bi = invmod(b, basen)
        a = (a * bi) & (basen - 1)
        c = (c * bi) & (basen - 1)
        b = 1

        x = (-c) & 1
        for i in range(1, basek):
            # lift solution x for 2^i to mod 2^{i+1}
            x = -(a*x*x + c) & ((1 << (i+1)) - 1)

        for i in range(1 << mp):
            yield x + (i << basek)

        return

    # reduce to x^2 + bx + c = 0
    ai = invmod(a, basen)
    b = (b * ai) & (basen - 1)
    c = (c * ai) & (basen - 1)
    a = 1

    if (b & 1) != 0:
        # if b is odd, we can't complete the square
        if (c & 1) != 0:
            # x^2 + bx is always even, so if c is odd there are no solutions
            return

        # b is odd and c is even => there are exactly two solutions x,y
        # and x+y === -b

        # start with an arbitrary solution mod 2 (both 0 and 1 are solutions)
        x = 0
        hb = (b - 1) >> 1
        for i in range(1, basek):
            # lift solution x for 2^i to mod 2^{i+1}
            x = -(x*x + 2*hb*x + c) & ((1 << (i+1)) - 1)

        for base in [x, (-b-x) & (basen - 1)]:
            for i in range(1 << mp):
                yield base + (i << basek)

        return

    # complete the square
    # (x + bx/2)^2 = (b/2)^2 - c
    rhs = ((b >> 1) ** 2 - c) & (basen - 1)

    try:
        for base in sqrtmod_prime_power(rhs, 2, basek):
            x = (base - (b >> 1)) & (basen - 1)
            for i in range(1 << mp):
                yield x + (i << basek)
    except ValueError:
        return

def solve_quadratic_mod_pk(a, b, c, p, k):
    ''' Calculate solutions to axx+bx+c === 0 mod p^k (where p is an odd prime) '''

    a %= p**k
    b %= p**k
    c %= p**k
    mp = 0

    if a == 0:
        # degenerate case
        for soln in solve_linear_mod_pk(b, c, p, k):
            yield soln
        return

    while (a % p) == 0 and (b % p) == 0 and (c % p) == 0 and mp < k:
        a /= p
        b /= p
        c /= p
        mp += 1

    basek = k - mp
    basen = p ** basek

    if (a % p) == 0:
        if (b % p) == 0:
            # p|a and p|b implies p/|c which is impossible
            return

        # there is a *unique* solution if p|a and p/|b
        bi = invmod(b, basen)
        a = (a * bi) % basen
        c = (c * bi) % basen
        b = 1

        x = (-c) % p
        curpow = p
        for i in range(1, basek):
            # lift solution x for p^i to mod p^{i+1}
            curpow *= p
            x = -(a*x*x + c) % curpow

        for i in range(p ** mp):
            yield x + i * basen

        return

    # reduce to x^2 + bx + c = 0
    ai = invmod(a, basen)
    b = (b * ai) % basen
    c = (c * ai) % basen
    a = 1

    # complete the square
    # (x + bx/2)^2 = (b/2)^2 - c
    hb = b * invmod(2, basen)
    rhs = (hb ** 2 - c) % basen

    try:
        for base in sqrtmod_prime_power(rhs, p, basek):
            x = (base - hb) % basen
            for i in range(p ** mp):
                yield x + i * basen
    except ValueError:
        return

def solve_quadratic_prime_power(a, b, c, p, k):
    if p == 2:
        return solve_quadratic_mod_2k(a, b, c, k)
    else:
        return solve_quadratic_mod_pk(a, b, c, p, k)

def solve_quadratic(a, b, c, factors):
    gens = []
    if isinstance(factors, dict):
        factors = list(factors.items())

    for p, k in factors:
        gens.append(solve_quadratic_prime_power(a, b, c, p, k))

    for solns in itertools.product(*gens):
        yield solve_crt(solns, [p**k for p,k in factors])
