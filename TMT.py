import hashlib
import random
import time
def fk(x, k):
    """
    f_k(x) = first k bits of SHA256(encode(x)).
    x is treated as a 4-byte big-endian integer.
    Output is in [0, 2^k).
    """
    h = hashlib.sha256(x.to_bytes(4, "big")).digest()
    return int.from_bytes(h, "big") >> (256 - k)
def step(x, k):
       return fk(x, k)
def build_table(k, m, t, seed = None):
    """
    Build Hellman table mapping endpoint -> starting point.
    m = number of chains
    t = chain length
    """
    if seed is not None:
        random.seed(seed)
    space = 1 << k
    table = {}
    for _ in range(m):
        sp = random.randrange(space)
        x = sp
        for _ in range(t):
            x = step(x, k)
        ep = x
        if ep not in table:
            table[ep] = sp
    return table
def recover_preimage(table, y, k, t):
    """
    Hellman online phase for fixed-length chains.
    Returns x such that f_k(x) = y if found, else None.
    """
    for j in range(t - 1, -1, -1):
        x = y
        for _ in range(t - 1 - j):
            x = step(x, k)
        ep = x
        sp = table.get(ep)
        if sp is None:
            continue
        cur = sp
        for _ in range(t):
            out = fk(cur, k)
            if out == y:
                return cur
            cur = out
    return None
def hexfmt(v, k):
    width = (k + 3) // 4
    return f"0x{v:0{width}x}"
def runCase(k, m, t, retries= 20):
    print(f"\nCASE k={k} ")
    print(f"parameters: m={m}, t={t}, space=2^{k}={1 << k}")
    t0 = time.time()
    table = build_table(k, m, t)
    t1 = time.time()
    print(f"Table size (unique endpoints): {len(table)}")
    print(f"precompute time: {t1 - t0:.3f}s")
    for attempt in range(1, retries + 1):
        x_real = random.randrange(1 << k)
        y = fk(x_real, k)
        t2 = time.time()
        x_found = recover_preimage(table, y, k, t)
        t3 = time.time()
        if x_found is not None and fk(x_found, k) == y:
            print(f"\nsuccess on attempt {attempt}")
            print(f"x_real  = {x_real} ({hexfmt(x_real, k)})")
            print(f"y       = {y} ({hexfmt(y, k)})")
            print(f"x_found = {x_found} ({hexfmt(x_found, k)})")
            print(f"check   = {fk(x_found, k) == y}")
            print(f"online time: {t3 - t2:.3f}s")
            return
    print(f"\nfailed after {retries} attempts.")
    print("try increasing m, t, or retries.")
def main():
    runCase(k=16, m=256, t=256, retries=10)
    runCase(k=20, m=1024, t=1024, retries=15)
    runCase(k=24, m=2048, t=2048, retries=30)
if __name__ == "__main__":
    main()