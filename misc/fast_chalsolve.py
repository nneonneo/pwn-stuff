# Solve a proof-of-work challenge fast.
# This is meant to be copy-pasted and edited as appropriate
# (specifically, the lines after '# changeme' should be edited
#  to reflect your actual PoW: prefix/postfix, hash function, and success condition).

def _solve_challenge_worker(arg):
    from hashlib import sha256
    from itertools import product

    i, s1, x, n, charset = arg
    print("proof of work ... %d" % (i*(len(charset)**n)))
    for s2 in product(charset, repeat=n):
        s = bytearray(s1 + s2)
        
        # changeme
        news = x + s
        if sha256(news).digest().startswith(b'\0\0\0'):
            return s

def solve_challenge(x, n, charset=b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
    ''' Solve a proof-of-work challenge with multiprocessing.

    x: known prefix/suffix
    n: number of extra chars to add
    charset: (optional) charset to use
    '''
    from itertools import product
    from multiprocessing import Pool

    n1 = 0
    while len(charset) ** n1 < 100000:
        n1 += 1
    if n1 > n:
        n1 = n // 2 + 1

    gen = ((i, s, x, n1, charset) for i, s in enumerate(product(charset, repeat=n-n1)))
    p = Pool()
    for res in p.imap_unordered(_solve_challenge_worker, gen):
        if res:
            p.terminate()
            return res
