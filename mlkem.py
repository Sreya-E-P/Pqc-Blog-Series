"""
mlkem.py - a small, readable ML-KEM (FIPS 203) implementation in pure Python.

FOR LEARNING AND TEST-VECTOR PRACTICE ONLY.
It is NOT constant-time and must never protect real secrets.

Structure follows the FIPS 203 algorithms:
    K-PKE (the inner public-key encryption)  ->  ML-KEM (FO transform on top)
"""
import hashlib

N = 256
Q = 3329
ZETA = 17

# (k, eta1, eta2, du, dv) for each parameter set
PARAMS = {
    'ML-KEM-512':  (2, 3, 2, 10, 4),
    'ML-KEM-768':  (3, 2, 2, 10, 4),
    'ML-KEM-1024': (4, 2, 2, 11, 5),
}


# ---------------------------------------------------------------- hashes
def H(b):            # SHA3-256
    return hashlib.sha3_256(b).digest()


def J(b):            # SHAKE256, 32 bytes out
    return hashlib.shake_256(b).digest(32)


def G(b):            # SHA3-512 split into two 32-byte halves
    d = hashlib.sha3_512(b).digest()
    return d[:32], d[32:]


def PRF(eta, s, b):  # SHAKE256(s || b), 64*eta bytes out
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


# ---------------------------------------------------------------- encoding
def byte_encode(f, d):
    """Pack 256 d-bit integers into 32*d bytes, little-endian bit order."""
    acc, nbits = 0, 0
    mask = (1 << d) - 1
    for x in f:
        acc |= (x & mask) << nbits
        nbits += d
    return acc.to_bytes(32 * d, 'little')


def byte_decode(b, d):
    acc = int.from_bytes(b, 'little')
    mask = (1 << d) - 1
    m = (1 << d) if d < 12 else Q
    return [((acc >> (d * i)) & mask) % m for i in range(N)]


def compress(x, d):
    return (((x << d) + Q // 2) // Q) % (1 << d)


def decompress(y, d):
    return (y * Q + (1 << (d - 1))) >> d


# ---------------------------------------------------------------- sampling
def sample_ntt(seed34):
    """Rejection-sample 256 coefficients mod q from SHAKE128 (Algorithm 7)."""
    stream = hashlib.shake_128(seed34).digest(840)  # plenty; extended if needed
    out, i, extra = [], 0, 840
    while len(out) < N:
        if i + 3 > len(stream):
            extra += 168
            stream = hashlib.shake_128(seed34).digest(extra)
        c0, c1, c2 = stream[i], stream[i + 1], stream[i + 2]
        i += 3
        d1 = c0 + 256 * (c1 % 16)
        d2 = (c1 >> 4) + 16 * c2
        if d1 < Q:
            out.append(d1)
        if d2 < Q and len(out) < N:
            out.append(d2)
    return out


def sample_cbd(b, eta):
    """Centered binomial distribution (Algorithm 8)."""
    bits = int.from_bytes(b, 'little')
    f = []
    for i in range(N):
        x = bin((bits >> (2 * i * eta)) & ((1 << eta) - 1)).count('1')
        y = bin((bits >> (2 * i * eta + eta)) & ((1 << eta) - 1)).count('1')
        f.append((x - y) % Q)
    return f


# ---------------------------------------------------------------- NTT
def _bitrev7(i):
    return int(format(i, '07b')[::-1], 2)


ZETAS = [pow(ZETA, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(ZETA, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def ntt(f):
    f = f[:]
    i, ln = 1, 128
    while ln >= 2:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i += 1
            for j in range(start, start + ln):
                t = (z * f[j + ln]) % Q
                f[j + ln] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        ln //= 2
    return f


def ntt_inv(f):
    f = f[:]
    i, ln = 127, 2
    while ln <= 128:
        for start in range(0, N, 2 * ln):
            z = ZETAS[i]
            i -= 1
            for j in range(start, start + ln):
                t = f[j]
                f[j] = (t + f[j + ln]) % Q
                f[j + ln] = (z * (f[j + ln] - t)) % Q
        ln *= 2
    return [(x * 3303) % Q for x in f]   # 3303 = 128^-1 mod q


def ntt_mul(f, g):
    h = [0] * N
    for i in range(128):
        a0, a1 = f[2 * i], f[2 * i + 1]
        b0, b1 = g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def vadd(a, b):
    return [(x + y) % Q for x, y in zip(a, b)]


def vsub(a, b):
    return [(x - y) % Q for x, y in zip(a, b)]


def _matrix(rho, k):
    # FIPS 203 uses rho || j || i for entry A[i][j]
    return [[sample_ntt(rho + bytes([j, i])) for j in range(k)] for i in range(k)]


# ---------------------------------------------------------------- K-PKE
def kpke_keygen(d, ps):
    k, eta1, _, _, _ = PARAMS[ps]
    rho, sigma = G(d + bytes([k]))
    A = _matrix(rho, k)
    n = 0
    s, e = [], []
    for _ in range(k):
        s.append(sample_cbd(PRF(eta1, sigma, n), eta1)); n += 1
    for _ in range(k):
        e.append(sample_cbd(PRF(eta1, sigma, n), eta1)); n += 1
    s_hat = [ntt(p) for p in s]
    e_hat = [ntt(p) for p in e]
    t_hat = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = vadd(acc, ntt_mul(A[i][j], s_hat[j]))
        t_hat.append(vadd(acc, e_hat[i]))
    ek = b''.join(byte_encode(p, 12) for p in t_hat) + rho
    dk = b''.join(byte_encode(p, 12) for p in s_hat)
    return ek, dk


def kpke_encrypt(ek, m, r, ps):
    k, eta1, eta2, du, dv = PARAMS[ps]
    t_hat = [byte_decode(ek[384 * i:384 * (i + 1)], 12) for i in range(k)]
    rho = ek[384 * k:]
    A = _matrix(rho, k)
    n = 0
    y, e1 = [], []
    for _ in range(k):
        y.append(sample_cbd(PRF(eta1, r, n), eta1)); n += 1
    for _ in range(k):
        e1.append(sample_cbd(PRF(eta2, r, n), eta2)); n += 1
    e2 = sample_cbd(PRF(eta2, r, n), eta2)
    y_hat = [ntt(p) for p in y]
    u = []
    for i in range(k):
        acc = [0] * N
        for j in range(k):
            acc = vadd(acc, ntt_mul(A[j][i], y_hat[j]))   # A transposed
        u.append(vadd(ntt_inv(acc), e1[i]))
    mu = [decompress(x, 1) for x in byte_decode(m, 1)]
    acc = [0] * N
    for j in range(k):
        acc = vadd(acc, ntt_mul(t_hat[j], y_hat[j]))
    v = vadd(vadd(ntt_inv(acc), e2), mu)
    c1 = b''.join(byte_encode([compress(x, du) for x in p], du) for p in u)
    c2 = byte_encode([compress(x, dv) for x in v], dv)
    return c1 + c2


def kpke_decrypt(dk, c, ps):
    k, _, _, du, dv = PARAMS[ps]
    c1, c2 = c[:32 * du * k], c[32 * du * k:]
    u = [[decompress(x, du) for x in byte_decode(c1[32 * du * i:32 * du * (i + 1)], du)]
         for i in range(k)]
    v = [decompress(x, dv) for x in byte_decode(c2, dv)]
    s_hat = [byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * N
    for j in range(k):
        acc = vadd(acc, ntt_mul(s_hat[j], ntt(u[j])))
    w = vsub(v, ntt_inv(acc))
    return byte_encode([compress(x, 1) for x in w], 1)


# ---------------------------------------------------------------- ML-KEM
def keygen_internal(d, z, ps):
    ek, dk_pke = kpke_keygen(d, ps)
    return ek, dk_pke + ek + H(ek) + z


def encaps_internal(ek, m, ps):
    K, r = G(m + H(ek))
    return K, kpke_encrypt(ek, m, r, ps)


def decaps_internal(dk, c, ps):
    k = PARAMS[ps][0]
    dk_pke = dk[:384 * k]
    ek = dk[384 * k:768 * k + 32]
    h = dk[768 * k + 32:768 * k + 64]
    z = dk[768 * k + 64:768 * k + 96]
    m2 = kpke_decrypt(dk_pke, c, ps)
    K2, r2 = G(m2 + h)
    K_bar = J(z + c)                        # implicit-rejection key
    c2 = kpke_encrypt(ek, m2, r2, ps)
    return K2 if c == c2 else K_bar         # (use a constant-time select in real code)


# ---------------------------------------------------------------- input checks (FIPS 203 sec. 7)
def ek_check(ek, ps):
    k = PARAMS[ps][0]
    if len(ek) != 384 * k + 32:
        return False
    for i in range(k):
        blk = ek[384 * i:384 * (i + 1)]
        if byte_encode(byte_decode(blk, 12), 12) != blk:   # modulus check
            return False
    return True


def dk_check(dk, ps):
    k = PARAMS[ps][0]
    if len(dk) != 768 * k + 96:
        return False
    return H(dk[384 * k:768 * k + 32]) == dk[768 * k + 32:768 * k + 64]
