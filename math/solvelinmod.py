from sage.all import *
import fpylll
import operator
from functools import reduce
import warnings

def solve_linear_mod(equations, bounds, means=None):
    ''' Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: M} entries, where var is a variable and M is the maximum of that variable (the bound).
        All variables used in the equations must be bounded.
    means: An *optional* dictionary containing the expected value (mean) of variables.
        Variables for which an expected value is not specified are assumed to lie uniformly in [0, bound),
        i.e. they will have a mean of bound/2.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds smaller and try again.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}
    '''

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).

    vars = list(bounds)
    if means is None:
        means = {}

    NR = len(equations)
    NV = len(vars)
    B = fpylll.IntegerMatrix(NR+NV, NR+NV)
    Y = [None] * (NR + NV)

    # B format (columns are the basis for the lattice):
    # [ eqns:NRxNV mods:NRxNR
    #   vars:NVxNV 0 ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)

    # Compute scale such that the variable axes can't interfere with the equation axes
    nS = 1
    for var in vars:
        nS = max(nS, int(bounds[var]).bit_length())
    # NR + NV is a fudge to make CVP return correct results despite the 2^(n/2) error bound
    S = (1 << (nS + (NR + NV + 1)))

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    scales = {}
    for vi, var in enumerate(vars):
        scale = S >> (int(bounds[var]).bit_length())
        scales[var] = scale
        # Fill in vars block of B
        B[NR + vi, vi] = scale
        # Fill in "guess" for variable axis - try reducing bounds if the result is wrong
        Y[NR + vi] = means.get(var, int(bounds[var]) >> 1) * scale

    # Extract coefficients from equations
    for ri, (rel, m) in enumerate(equations):
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError('relation %s: not an equality relation' % rel)

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in bounds:
                raise ValueError('relation %s: variable %s is not bounded' % (rel, var))

        # Fill in eqns block of B
        coeffs = []
        for vi, var in enumerate(vars):
            if expr.degree(var) >= 2:
                raise ValueError('relation %s: equation is not linear in %s' % (rel, var))
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError('relation %s: coefficient of %s is not constant (equation is not linear)' % (rel, var))
            if not coeff.is_integer():
                raise ValueError('relation %s: coefficient of %s is not an integer' % (rel, var))

            B[ri, vi] = (int(coeff) % m) * S

        # Fill in mods block of B
        B[ri, NV + ri] = m * S

        const = expr.subs({var: 0 for var in vars})
        if not const.is_constant():
            raise ValueError('relation %s: failed to extract constant' % rel)
        if not const.is_integer():
            raise ValueError('relation %s: constant is not integer' % rel)

        # Fill in corresponding equation axes of target Y
        Y[ri] = (int(-const) % m) * S

    # Note that CVP requires LLL to be run first, and that LLL/CVP use the rows as the basis
    Bt = B.transpose()
    lll = fpylll.LLL.reduction(Bt)
    result = fpylll.CVP.closest_vector(Bt, Y)

    # Check result for sanity
    if list(map(int, result[:NR])) != list(map(int, Y[:NR])):
        raise ValueError("CVP returned an incorrect result: input %s, output %s (try increasing your bounds?)" % (Y, result))

    res = {}
    for vi, var in enumerate(vars):
        aa = result[NR + vi] // scales[var]
        bb = result[NR + vi] % scales[var]
        if bb:
            warnings.warn("CVP returned suspicious result: %s=%d is not scaled correctly (try adjusting your bounds?)" % (var, result[NR + vi]))
        res[var] = aa

    return res

if __name__ == '__main__':
    import hashlib

    def sha1(x):
        return int(hashlib.sha1(x.encode()).hexdigest(), 16)


    ## DSA with LCG nonces, https://id0-rsa.pub/problem/44/
    m1, r1, s1 = (
        sha1("message1"),
        202861689990073510420857440842954393147681706677,
        316598684468735233298185340984928938581112602589
    )
    m2, r2, s2 = (
        sha1("message2"),
        43602034738807436825901197549075276008737747591,
        642028161610139974743754581527505118749777770326
    )
    q = 0x00d5f00a9c48d145920784bfb1a56b1f1f95e7f747
    a = 545094182407654161786276305190438612396347946877
    c = 106527113109554186270186272440947601748633355206
    m = 983310466739698185049446758331422281214830590642
    x, k1, k2 = var('x,k1,k2')
    solution = solve_linear_mod([
        (-r1*x + s1*k1 == m1, q),
        (-r2*x + s2*k2 == m2, q),
        (k2 == a*k1 + c, m)
    ], {x: q, k1: m, k2: m})
    assert solution[x] == 0x29f482f543621c402e2dc2a599c5dde82095bf4f


    ## DEFCON Qualifiers 2019, Tania
    # Nested double LCG
    q = 834233754607844004570804297965577358375283559517

    r1 = 339852212809401285169513788469136059609698880879
    s1 = 496790200514422465789023998822262264488035638851
    r2 = 324174312750227948893199440329947234731609961206
    s2 = 639257804075062383136332063839942735294232544871

    A1 = 864337018519190491905529980744
    B1 = 536243723865963036490538290474
    M1 = 1063010345787496234374101456994
    A2 = 813460733623680327018793997863
    B2 = 68174629230356751334120213815
    M2 = 149969575537638328028522091955
    C1 = 1236621443694604088636495657553
    C2 = 360116617412226281615057993787
    BB = 557068474970796394723013869302
    M = 621722243779663917170959398660

    m1 = sha1("the rules are the rules, no complaints")
    m2 = sha1("reyammer can change the rules")

    x, k1, k2, t1, t2 = var('x,k1,k2,t1,t2')
    solution = solve_linear_mod([
        (-r1*x + s1*k1 == m1, q),
        (-r2*x + s2*k2 == m2, q),
        (t1 == A1*k1 + B1, M1),
        (t2 == A2*k1 + B2, M2),
        (k2 == t1*C1 + t2*C2 + BB, M),
    ], {x: q, k1: M, k2: M, t1: M1, t2: M2})

    assert solution[x] == 207059656384708398671740962281764769375058273661


    ## Generalization of Samsung CTF Finals 2018 LCG problem
    # secret parameters: s0, s1, x, y, z, m
    s0 = 3005423129600575593
    s1 = 7396509365641243733
    x = 8169846461236506548
    y = 5748392989531061213
    z = 15303690528977248313
    m = 15674144604358019630
    expsoln = {'x': x, 'y': y, 'z': z, 'm': m}

    ks = []
    for i in range(9):
        s0, s1 = s1, (x*s1 + y*s0 + z) % m
        ks.append(s1)

    # don't cheat
    del s0, s1, x, y, z, m

    # solve for m
    ds = []
    for i in range(1, 9):
        # remove z: ds[i] = x*ds[i-1] + y*d[i-2]
        ds.append(ks[i] - ks[i-1])

    dds = []
    for i in range(1, 7):
        # remove x: dds[i] = -y*dds[i-1]
        dds.append(ds[i]*ds[i] - ds[i-1]*ds[i+1])

    ddds = []
    for i in range(1, 5):
        # remove y: ddds[i] = 0 mod m
        ddds.append(dds[i]*dds[i] - dds[i-1]*dds[i+1])

    # note: this does not always work - sometimes m' ends up as a multiple of m
    m = reduce(gcd, ddds)
    assert m == expsoln['m']

    # n.b. we can also solve this using
    # y = -inverse_mod(dds[0], m) * dds[1] % m
    # x = (ds[2] - y*ds[0]) * inverse_mod(ds[1], m) % m
    # z = (ks[2] - ks[1]*x - ks[0]*y) % m

    x, y, z = var('x,y,z')
    eqns = []
    bounds = {x: m, y: m, z: m}
    for i in range(2, 7):
        eqns.append((ks[i] == x*ks[i-1] + y*ks[i-2] + z, m))

    solution = solve_linear_mod(eqns, bounds)
    assert solution[x] % m == expsoln['x'] % m
    assert solution[y] % m == expsoln['y'] % m
    assert solution[z] % m == expsoln['z'] % m


    ## Truncated LCG
    mod = (1 << 32)
    # random a/b parameters
    a = 0xd0ab4379
    b = 0xa34a85d3
    shift = 20
    nout = 3
    # unknown initial state
    ostate = state = 0x174c562a
    # run LCG generator to produce truncated outputs
    output = []
    for i in range(nout):
        state = (state * a + b) % mod
        output.append(state >> shift)

    # start solving given output
    state = var('state')
    statevar = state
    eqns = []
    bounds = {state: mod}
    # rerun LCG generator with an unknown initial state
    for i in range(nout):
        state = (state * a + b)
        # ti are unknown low-order bits
        ti = var('t%d' % i)
        bounds[ti] = (1 << shift)
        eqns.append((state - ti == (output[i] << shift), mod))
    # this equation is *underdetermined* because of the ti's,
    # but because they're bounded, this is still solvable
    solution = solve_linear_mod(eqns, bounds)
    assert solution[statevar] % mod == ostate
