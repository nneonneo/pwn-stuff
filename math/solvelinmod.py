"""
Solve a bounded system of modular linear equations.

(c) 2019-2022 Robert Xiao <nneonneo@gmail.com>
https://robertxiao.ca

Originally developed in May 2019; updated July 2022

Please mention this software if it helps you solve a challenge!
"""

from collections.abc import Sequence
import math
import operator
from typing import List, Tuple

from sage.all import ZZ, gcd, matrix, prod, var


def _process_linear_equations(equations, vars, guesses) -> List[Tuple[List[int], int, int]]:
    result = []

    for rel, m in equations:
        op = rel.operator()
        if op is not operator.eq:
            raise TypeError(f"relation {rel}: not an equality relation")

        expr = (rel - rel.rhs()).lhs().expand()
        for var in expr.variables():
            if var not in vars:
                raise ValueError(f"relation {rel}: variable {var} is not bounded")

        # Fill in eqns block of B
        coeffs = []
        for var in vars:
            if expr.degree(var) >= 2:
                raise ValueError(f"relation {rel}: equation is not linear in {var}")
            coeff = expr.coefficient(var)
            if not coeff.is_constant():
                raise ValueError(f"relation {rel}: coefficient of {var} is not constant (equation is not linear)")
            if not coeff.is_integer():
                raise ValueError(f"relation {rel}: coefficient of {var} is not an integer")

            coeffs.append(int(coeff) % m)

        # Shift variables towards their guesses to reduce the (expected) length of the solution vector
        const = expr.subs({var: guesses[var] for var in vars})
        if not const.is_constant():
            raise ValueError(f"relation {rel}: failed to extract constant")
        if not const.is_integer():
            raise ValueError(f"relation {rel}: constant is not integer")

        const = int(const) % m

        result.append((coeffs, const, m))

    return result


def solve_linear_mod(equations, bounds, verbose=False, **lll_args):
    """Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: B} entries, where var is a variable and B is the bounds on that variable.
        Bounds may be specified in one of three ways:
        - A single integer X: Variable is assumed to be uniformly distributed in [0, X] with an expected value of X/2.
        - A tuple of integers (X, Y): Variable is assumed to be uniformly distributed in [X, Y] with an expected value of (X + Y)/2.
        - A tuple of integers (X, E, Y): Variable is assumed to be bounded within [X, Y] with an expected value of E.
        All variables used in the equations must be bounded.
    verbose: set to True to enable additional output
    lll_args: Additional arguments passed to LLL, for advanced usage.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, and the result
    is incorrect, make some bounds tighter and try again.

    Tip: if you get an unwanted solution, try setting the expected values to that solution to force this function
    to produce a different solution.

    Tip: if your bounds are loose and you just want small solutions, set the expected values to zero for all
    loosely-bounded variables.

    >>> k = var('k')
    >>> # solve CRT
    >>> solve_linear_mod([(k == 2, 3), (k == 4, 5), (k == 3, 7)], {k: 3*5*7})
    {k: 59}

    >>> x,y = var('x,y')
    >>> solve_linear_mod([(2*x + 3*y == 7, 11), (3*x + 5*y == 3, 13), (2*x + 5*y == 6, 143)], {x: 143, y: 143})
    {x: 62, y: 5}

    >>> x,y = var('x,y')
    >>> # we can also solve homogenous equations, provided the guesses are zeroed
    >>> solve_linear_mod([(2*x + 5*y == 0, 1337)], {x: 5, y: 5}, guesses={x: 0, y: 0})
    {x: 5, y: -2}
    """

    # The general idea is to set up an integer matrix equation Ax=y by introducing extra variables for the quotients,
    # then use LLL to solve the equation. We introduce extra axes in the lattice to observe the actual solution x,
    # which works so long as the solutions are known to be bounded (which is of course the case for modular equations).
    # Scaling factors are configured to generally push the smallest vectors to have zeros for the relations, and to
    # scale disparate variables to approximately the same base.

    vars = list(bounds)
    guesses = {}
    var_scale = {}
    for var in vars:
        bound = bounds[var]
        if isinstance(bound, Sequence):
            if len(bound) == 2:
                xmin, xmax = map(int, bound)
                guess = (xmax - xmin) // 2 + xmin
            elif len(bound) == 3:
                xmin, guess, xmax = map(int, bound)
            else:
                raise TypeError("Bounds must be integers, 2-tuples or 3-tuples")
        else:
            xmin = 0
            xmax = int(bound)
            guess = xmax // 2
        if not xmin <= guess <= xmax:
            raise ValueError(f"Bound for variable {var} is invalid ({xmin=} {guess=} {xmax=})")
        var_scale[var] = max(xmax - guess, guess - xmin, 1)
        guesses[var] = guess

    var_bits = math.log2(int(prod(var_scale.values()))) + len(vars)
    mod_bits = math.log2(int(prod(m for rel, m in equations)))
    if verbose:
        print(f"verbose: variable entropy: {var_bits:.2f} bits")
        print(f"verbose: modulus entropy: {mod_bits:.2f} bits")

    # Extract coefficients from equations
    equation_coeffs = _process_linear_equations(equations, vars, guesses)

    is_inhom = any(const != 0 for coeffs, const, m in equation_coeffs)

    NR = len(equation_coeffs)
    NV = len(vars)
    if is_inhom:
        # Add one dummy variable for the constant term.
        NV += 1
    B = matrix(ZZ, NR + NV, NR + NV)

    # B format (rows are the basis for the lattice):
    # [ mods:NRxNR 0
    #   eqns:NVxNR vars:NVxNV ]
    # eqns correspond to equation axes, fi(...) = yi mod mi
    # vars correspond to variable axes, which effectively "observe" elements of the solution vector (x in Ax=y)
    # mods and vars are diagonal, so this matrix is lower triangular.

    # Compute maximum scale factor over all variables
    S = max(var_scale.values())

    # Compute equation scale such that the bounded solution vector (equation columns all zero)
    # will be shorter than any vector that has a nonzero equation column
    eqS = S << (NR + NV + 1)
    # If the equation is underconstrained, add additional scaling to find a solution anyway
    if var_bits > mod_bits:
        eqS <<= int((var_bits - mod_bits) / NR) + 1
    col_scales = []

    for ri, (coeffs, const, m) in enumerate(equation_coeffs):
        for vi, c in enumerate(coeffs):
            B[NR + vi, ri] = c
        if is_inhom:
            B[NR + NV - 1, ri] = const
        col_scales.append(eqS)
        B[ri, ri] = m

    # Compute per-variable scale such that the variable axes are scaled roughly equally
    for vi, var in enumerate(vars):
        col_scales.append(S // var_scale[var])
        # Fill in vars block of B
        B[NR + vi, NR + vi] = 1

    if is_inhom:
        # Const block: effectively, this is a bound of 1 on the constant term
        col_scales.append(S)
        B[NR + NV - 1, -1] = 1

    if verbose:
        print("verbose: scaling shifts:", [math.log2(int(s)) for s in col_scales])
        print("verbose: unscaled matrix before:")
        print(B.n())

    for i, s in enumerate(col_scales):
        B[:, i] *= s
    B = B.LLL(**lll_args)
    for i, s in enumerate(col_scales):
        B[:, i] /= s

    # Negate rows for more readable output
    for i in range(B.nrows()):
        if sum(x < 0 for x in B[i, :]) > sum(x > 0 for x in B[i, :]):
            B[i, :] *= -1
        if is_inhom and B[i, -1] < 0:
            B[i, :] *= -1

    if verbose:
        print("verbose: unscaled matrix after:")
        print(B.n())

    for row in B:
        if any(x != 0 for x in row[:NR]):
            # invalid solution: some relations are nonzero
            continue

        if is_inhom:
            # Each row is a potential solution, but some rows may not carry a constant.
            if row[-1] != 1:
                if verbose:
                    print(
                        "verbose: zero solution",
                        {var: row[NR + vi] for vi, var in enumerate(vars) if row[NR + vi] != 0},
                    )
                continue

        res = {}
        for vi, var in enumerate(vars):
            res[var] = row[NR + vi] + guesses[var]

        return res


def demo_1():
    """DSA with LCG nonces, https://id0-rsa.pub/problem/44/

    We are given P, Q, and G. An LCG was used to generate nonces to sign two messages.
    Using the fact that the nonces are related, we can recover the signing key."""

    import hashlib

    def sha1(x):
        return int(hashlib.sha1(x.encode()).hexdigest(), 16)

    m1, r1, s1 = (
        sha1("message1"),
        202861689990073510420857440842954393147681706677,
        316598684468735233298185340984928938581112602589,
    )
    m2, r2, s2 = (
        sha1("message2"),
        43602034738807436825901197549075276008737747591,
        642028161610139974743754581527505118749777770326,
    )
    q = 0x00D5F00A9C48D145920784BFB1A56B1F1F95E7F747
    a = 545094182407654161786276305190438612396347946877
    c = 106527113109554186270186272440947601748633355206
    m = 983310466739698185049446758331422281214830590642
    x, k1, k2 = var("x,k1,k2")
    solution = solve_linear_mod(
        [
            (-r1 * x + s1 * k1 == m1, q),
            (-r2 * x + s2 * k2 == m2, q),
            (k2 == a * k1 + c, m),
        ],
        {x: q, k1: m, k2: m},
    )
    print(solution)
    assert solution[x] == 0x29F482F543621C402E2DC2A599C5DDE82095BF4F


def demo_2():
    """DSA with nested double-LCG nonces (Tania challenge, DEFCON 2019 Qualifiers)

    One pair of messages is sufficient to break this scheme (even though you can get more message
    pairs if you want).
    """

    import hashlib

    def sha1(x):
        return int(hashlib.sha1(x.encode()).hexdigest(), 16)

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

    x, k1, k2, t1, t2 = var("x,k1,k2,t1,t2")
    solution = solve_linear_mod(
        [
            (-r1 * x + s1 * k1 == m1, q),
            (-r2 * x + s2 * k2 == m2, q),
            (t1 == A1 * k1 + B1, M1),
            (t2 == A2 * k1 + B2, M2),
            (k2 == t1 * C1 + t2 * C2 + BB, M),
        ],
        {x: q, k1: M, k2: M, t1: M1, t2: M2},
    )

    print(solution)
    assert solution[x] == 207059656384708398671740962281764769375058273661


def demo_3():
    """Solve for the parameters of a bilinear LCG using only a few observed outputs.

    This is a generalization from the LCG problem from Samsung CTF Finals 2018.
    """
    from functools import reduce

    # secret parameters: s0, s1, x, y, z, m
    s0 = 3005423129600575593
    s1 = 7396509365641243733
    x = 8169846461236506548
    y = 5748392989531061213
    z = 15303690528977248313
    m = 15674144604358019630
    expsoln = {"x": x, "y": y, "z": z, "m": m}

    ks = []
    for i in range(9):
        s0, s1 = s1, (x * s1 + y * s0 + z) % m
        ks.append(s1)

    # don't cheat
    del s0, s1, x, y, z, m

    # solve for m first
    ds = []
    for i in range(1, 9):
        # remove z: ds[i] = x*ds[i-1] + y*d[i-2]
        ds.append(ks[i] - ks[i - 1])

    dds = []
    for i in range(1, 7):
        # remove x: dds[i] = -y*dds[i-1]
        dds.append(ds[i] * ds[i] - ds[i - 1] * ds[i + 1])

    ddds = []
    for i in range(1, 5):
        # remove y: ddds[i] = 0 mod m
        ddds.append(dds[i] * dds[i] - dds[i - 1] * dds[i + 1])

    # note: this does not always work - sometimes m' ends up as a multiple of m
    m = reduce(gcd, ddds)
    assert m == expsoln["m"]

    # n.b. we can also solve this challenge using
    # y = -inverse_mod(dds[0], m) * dds[1] % m
    # x = (ds[2] - y*ds[0]) * inverse_mod(ds[1], m) % m
    # z = (ks[2] - ks[1]*x - ks[0]*y) % m

    x, y, z = var("x,y,z")
    eqns = []
    bounds = {x: m, y: m, z: m}
    for i in range(2, 7):
        eqns.append((ks[i] == x * ks[i - 1] + y * ks[i - 2] + z, m))

    solution = solve_linear_mod(eqns, bounds)
    print(solution)
    assert solution[x] % m == expsoln["x"] % m
    assert solution[y] % m == expsoln["y"] % m
    assert solution[z] % m == expsoln["z"] % m


def demo_4():
    """ Generic demonstration on how to recover the seed for a truncated LCG. """

    mod = 1 << 32
    # random a/b parameters
    a = 0xD0AB4379
    b = 0xA34A85D3
    shift = 20
    nout = 3
    # unknown initial state
    ostate = state = 0x174C562A
    # run LCG generator to produce truncated outputs
    output = []
    for i in range(nout):
        state = (state * a + b) % mod
        output.append(state >> shift)

    # start solving given output
    state = var("state")
    statevar = state
    eqns = []
    bounds = {state: mod}
    # rerun LCG generator with an unknown initial state
    for i in range(nout):
        state = state * a + b
        # ti are unknown low-order bits
        ti = var("t%d" % i)
        bounds[ti] = 1 << shift
        eqns.append((state - ti == (output[i] << shift), mod))
    # this equation is *underdetermined* because of the ti's,
    # but because they're bounded, this is still solvable
    solution = solve_linear_mod(eqns, bounds)
    print(solution)
    assert solution[statevar] % mod == ostate


if __name__ == "__main__":
    demo_1()
    demo_2()
    demo_3()
    demo_4()
