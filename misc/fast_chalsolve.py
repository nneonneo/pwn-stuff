# Solve a proof-of-work challenge fast.
# This is meant to be copy-pasted and edited as appropriate
# (specifically, the lines after '# changeme' should be edited
#  to reflect your actual PoW: prefix/postfix, hash function, and success condition).

def _solve_challenge_worker(arg):
    from rxpwn import log
    from hashlib import sha1
    from itertools import product

    i, s1, x, n, charset = arg
    log("proof of work ...", i*(len(charset)**n))
    for s2 in product(charset, repeat=n):
        s = ''.join(s1 + s2)
        
        # changeme
        news = x + s
        if sha1(news).digest().endswith('\xff\xff\xff'):
            return news

def solve_challenge(x, n, charset='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
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
