from sage.all import *
import fpylll
import operator

def solve_linear_mod(equations, bounds):
    ''' Solve an arbitrary system of modular linear equations over different moduli.

    equations: A sequence of (lhs == rhs, M) pairs, where lhs and rhs are expressions and M is the modulus.
    bounds: A dictionary of {var: M} entries, where var is a variable and M is the maximum of that variable (the bound).
        All variables used in the equations must be bounded.

    NOTE: Bounds are *soft*. This function may return solutions above the bounds. If this happens, make some bounds
    much smaller and try again.

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
        Y[NR + vi] = (int(bounds[var]) / 2) * scale

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

            B[ri, vi] = int(coeff) * S

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
    if map(int, result[:NR]) != map(int, Y[:NR]):
        raise ValueError("CVP returned an incorrect result: input %s, output %s" % (Y, result))
    res = {}
    for vi, var in enumerate(vars):
        aa, bb = divmod(result[NR + vi], scales[var])
        if bb:
            import warnings
            warnings.warn("CVP returned suspicious result: %s=%d is not scaled correctly" % (var, result[NR + vi]))
        res[var] = aa

    return res
