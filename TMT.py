import hashlib
import random
import math
import time
def fk(x, k):
    """
    Return the first k bits of SHA256(x), where x is encoded as 4 bytes.
    Output is always in the range [0, 2^k - 1].
    """
    digest = hashlib.sha256(x.to_bytes(4, "big")).digest()
    value = int.from_bytes(digest, "big")
    return value >> (256 - k)


def reduction(y, k):
    """
    Map the k-bit hash output back into the same k-bit input space.
    This helps reduce chain merging compared to using fk() directly.
    """
    mask = (1 << k) - 1
    return (1103515245 * y + 12345) & mask


def step(x, k):
    """
    One Hellman chain step:
        x -> fk(x) -> reduction(...)
    """
    y = fk(x, k)
    return reduction(y, k)


def build_table(k, m, t, seed= None):
    """
    Build one Hellman table as a dictionary:
        endpoint -> starting point

    k = number of bits in truncated SHA256 output
    m = number of chains
    t = chain length
    """
    if seed is not None:
        random.seed(seed)

    space_size = 1 << k
    table= {}

    for _ in range(m):
        start_point = random.randrange(space_size)
        x = start_point

        for _ in range(t):
            x = step(x, k)

        end_point = x

        if end_point not in table:
            table[end_point] = start_point

    return table


def recoverPreimage(table, target_y, k, t):
    """
    Online Hellman lookup phase.
    Try to find some x such that fk(x, k) == target_y.
    Returns x if found, otherwise None.
    """
    for j in range(t - 1, -1, -1):
        x = reduction(target_y, k)

        for _ in range(t - 1 - j):
            x = step(x, k)

        end_point = x
        start_point = table.get(end_point)

        if start_point is None:
            continue

        current = start_point

        for _ in range(t):
            y = fk(current, k)
            if y == target_y:
                return current
            current = step(current, k)

    return None


def hex_format(value, k):
    width = (k + 3) // 4
    return f"0x{value:0{width}x}"


def estimated_coverage(m, t, k):
    """
    Very rough Hellman-style coverage estimate ignoring merges:
        coverage ≈ 1 - exp(-m*t / 2^k)
    """
  
    return 1 - math.exp(-(m * t) / (1 << k))


def run_case(k, m, t, retries = 20, seed = None):
    print(f"\nCASE k={k}")
    print(f"parameters: m={m}, t={t}, space=2^{k}={1 << k}")
    print(f"estimated coverage ≈ {estimated_coverage(m, t, k):.4f}")

    start_build = time.time()
    table = build_table(k, m, t, seed=seed)
    end_build = time.time()

    print(f"table size (unique endpoints): {len(table)}")
    print(f"precompute time: {end_build - start_build:.3f}s")

    for attempt in range(1, retries + 1):
        x_real = random.randrange(1 << k)
        y = fk(x_real, k)

        start_online = time.time()
        x_found = recoverPreimage(table, y, k, t)
        end_online = time.time()

        if x_found is not None and fk(x_found, k) == y:
            print(f"\nsuccess on attempt {attempt}")
            print(f"x_real  = {x_real} ({hex_format(x_real, k)})")
            print(f"y       = {y} ({hex_format(y, k)})")
            print(f"x_found = {x_found} ({hex_format(x_found, k)})")
            print(f"check   = {fk(x_found, k) == y}")
            print(f"online time: {end_online - start_online:.3f}s")
            return

    print(f"\nfailed after {retries} attempts.")
    print("try increasing m, t, or retries.")


def main():
    # 16-bit toy case
    run_case(k=16, m=256, t=256, retries=10, seed=42)

    # 20-bit case
    run_case(k=20, m=1024, t=1024, retries=15, seed=42)

    # 24-bit case
    run_case(k=24, m=4096, t=4096, retries=30, seed=42)


if __name__ == "__main__":
    main()