#!/usr/bin/env python3
"""
Lab 4 - Signature algorithms compared: Falcon vs ML-DSA vs SLH-DSA vs ECDSA/Ed25519

Needs liboqs + liboqs-python (you built both in Lab 1 of the guide):  import oqs
Classical baselines use the 'cryptography' package.

Reports, per algorithm:
  * public key / secret key / signature sizes
  * keygen, sign, verify time: mean, median, p99 (microseconds)
  * "auth bytes" estimate for a TLS 1.3 handshake with a 2-certificate chain

Why p99 matters: ML-DSA signing uses rejection sampling and Falcon signing uses a
randomised sampler, so signing time VARIES. Mean alone hides the tail.

    python3 04_sig_bench.py              # default sample counts
    python3 04_sig_bench.py --quick      # fewer iterations
"""
import argparse
import csv
import statistics
import time

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

CANDIDATES = [
    ('ML-DSA-44',          ['ML-DSA-44']),
    ('ML-DSA-65',          ['ML-DSA-65']),
    ('ML-DSA-87',          ['ML-DSA-87']),
    ('Falcon-512',         ['Falcon-512', 'FN-DSA-512']),
    ('Falcon-1024',        ['Falcon-1024', 'FN-DSA-1024']),
    ('SLH-DSA-SHA2-128f',  ['SLH-DSA-SHA2-128f', 'SLH_DSA_PURE_SHA2_128F', 'SPHINCS+-SHA2-128f-simple']),
    ('SLH-DSA-SHA2-128s',  ['SLH-DSA-SHA2-128s', 'SLH_DSA_PURE_SHA2_128S', 'SPHINCS+-SHA2-128s-simple']),
]
MSG = b'The quick brown fox signs a TLS transcript hash ' * 2


def resolve(names):
    enabled = set(oqs.get_enabled_sig_mechanisms())
    for n in names:
        if n in enabled:
            return n
    return None


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


def stats_us(samples):
    us = [x * 1e6 for x in samples]
    return statistics.mean(us), statistics.median(us), pct(us, 99)


def timeit(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append(time.perf_counter() - t)
    return out


def bench_oqs(name, n_kg, n_sig):
    with oqs.Signature(name) as s:
        pk = s.generate_keypair()
        sk_len = s.details['length_secret_key']
        sig = s.sign(MSG)
        assert s.verify(MSG, sig, pk)
        kg = timeit(lambda: oqs.Signature(name).generate_keypair(), n_kg)
        sg = timeit(lambda: s.sign(MSG), n_sig)
        vf = timeit(lambda: s.verify(MSG, sig, pk), n_sig)
        # tamper check: verification must fail on a modified message
        assert not s.verify(MSG + b'x', sig, pk)
    return len(pk), sk_len, len(sig), kg, sg, vf


def bench_ecdsa(n_kg, n_sig):
    sk = ec.generate_private_key(ec.SECP256R1())
    pk = sk.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pk_len = len(pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint))
    sig = sk.sign(MSG, ec.ECDSA(hashes.SHA256()))
    kg = timeit(lambda: ec.generate_private_key(ec.SECP256R1()), n_kg)
    sg = timeit(lambda: sk.sign(MSG, ec.ECDSA(hashes.SHA256())), n_sig)
    vf = timeit(lambda: pk.verify(sig, MSG, ec.ECDSA(hashes.SHA256())), n_sig)
    return pk_len, 32, len(sig), kg, sg, vf   # DER sig is ~70-72 B


def bench_ed25519(n_kg, n_sig):
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    sig = sk.sign(MSG)
    kg = timeit(lambda: ed25519.Ed25519PrivateKey.generate(), n_kg)
    sg = timeit(lambda: sk.sign(MSG), n_sig)
    vf = timeit(lambda: pk.verify(sig, MSG), n_sig)
    return 32, 32, len(sig), kg, sg, vf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quick', action='store_true')
    a = ap.parse_args()
    n_kg, n_sig = (5, 50) if a.quick else (30, 300)

    print(f'liboqs {oqs.oqs_version()}  |  liboqs-python {oqs.oqs_python_version()}')
    rows = []
    rows.append(('ECDSA P-256',) + bench_ecdsa(n_kg, n_sig))
    rows.append(('Ed25519',) + bench_ed25519(n_kg, n_sig))
    for label, names in CANDIDATES:
        name = resolve(names)
        if not name:
            print(f'(skipping {label}: not enabled in this liboqs build)')
            continue
        k = 3 if 'SLH' in label and label.endswith('s') else n_kg      # 's' sets sign slowly
        s = 10 if 'SLH' in label and label.endswith('s') else (60 if 'SLH' in label else n_sig)
        rows.append((label,) + bench_oqs(name, k, s))

    hdr = (f'{"algorithm":20s} {"pk B":>6s} {"sk B":>6s} {"sig B":>6s} | '
           f'{"keygen us (mean)":>16s} | {"sign us mean / p50 / p99":>28s} | {"verify us mean / p99":>22s}')
    print('\n' + hdr)
    print('-' * len(hdr))
    out = []
    for label, pk, sk, sg, kg, sgn, vf in rows:
        km, _, _ = stats_us(kg)
        sm, s50, s99 = stats_us(sgn)
        vm, _, v99 = stats_us(vf)
        print(f'{label:20s} {pk:6d} {sk:6d} {sg:6d} | {km:16.1f} | '
              f'{sm:10.1f} /{s50:8.1f} /{s99:8.1f} | {vm:10.1f} /{v99:8.1f}')
        out.append([label, pk, sk, sg, f'{km:.1f}', f'{sm:.1f}', f'{s50:.1f}', f'{s99:.1f}',
                    f'{vm:.1f}', f'{v99:.1f}'])

    print('\nEstimated authentication bytes in a TLS 1.3 handshake (2 certs sent + CertificateVerify):')
    print('  = 2 x (public key + signature) + 1 x signature      [ignores X.509 overhead]')
    for label, pk, sk, sg, *_ in rows:
        print(f'  {label:20s} {2 * (pk + sg) + sg:8d} bytes')

    print('\nReading guide:')
    print('  * Falcon: smallest PQ signatures, but keygen is slow and signing needs floating-point math,')
    print('    which is hard to make constant-time. Verification is fast.')
    print('  * ML-DSA: the general-purpose pick. Compare mean vs p99 signing time (rejection sampling).')
    print('  * SLH-DSA: tiny keys, huge signatures, slow signing. Right for roots/firmware, not TLS leaves.')

    with open('sig_results.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['algorithm', 'pk_bytes', 'sk_bytes', 'sig_bytes', 'keygen_us_mean',
                    'sign_us_mean', 'sign_us_p50', 'sign_us_p99', 'verify_us_mean', 'verify_us_p99'])
        w.writerows(out)
    print('\nSaved sig_results.csv')


if __name__ == '__main__':
    main()
