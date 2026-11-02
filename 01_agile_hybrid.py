#!/usr/bin/env python3
"""
Lab 1 - Crypto-agility + Hybrid PQC + ECDH + AES-256-GCM

One small program that shows:
  * a SUITE REGISTRY: algorithms are looked up by name, never hard-coded
  * classical KEMs built from ECDH (X25519, P-256, P-384)
  * ML-KEM (from mlkem.py, the pure-Python FIPS 203 you built)
  * HYBRID KEMs: classical + ML-KEM, secrets combined with HKDF
  * an AES-256-GCM envelope whose AAD binds the suite name (anti-downgrade)
  * a benchmark of every suite (time + bytes on the wire)

Run:
    python3 01_agile_hybrid.py demo   --suite hybrid-x25519-mlkem768
    python3 01_agile_hybrid.py demo   --suite ecdh-p256
    python3 01_agile_hybrid.py tamper --suite hybrid-x25519-mlkem768
    python3 01_agile_hybrid.py bench  --runs 20
    python3 01_agile_hybrid.py policy                # read suite from policy.json

NOTE: mlkem.py is pure Python and NOT constant-time. Use it to learn and to
measure sizes; use liboqs/OpenSSL for real speed and real secrets.
"""
import argparse
import json
import os
import statistics
import sys
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import mlkem

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
X962 = dict(encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)


# ======================================================================
# KEM interface:  keygen() -> (public_bytes, private_obj)
#                 encaps(public_bytes) -> (ciphertext, shared_secret)
#                 decaps(private_obj, ciphertext) -> shared_secret
# ======================================================================
class X25519KEM:
    """ECDH used as a KEM: the 'ciphertext' is the sender's ephemeral public key."""
    pk_len = ct_len = 32

    def keygen(self):
        sk = x25519.X25519PrivateKey.generate()
        return sk.public_key().public_bytes(**RAW), sk

    def encaps(self, pk):
        eph = x25519.X25519PrivateKey.generate()
        ss = eph.exchange(x25519.X25519PublicKey.from_public_bytes(pk))
        return eph.public_key().public_bytes(**RAW), ss

    def decaps(self, sk, ct):
        return sk.exchange(x25519.X25519PublicKey.from_public_bytes(ct))


class ECDHKEM:
    def __init__(self, curve, size):
        self.curve, self.pk_len = curve, size

    @property
    def ct_len(self):
        return self.pk_len

    def keygen(self):
        sk = ec.generate_private_key(self.curve())
        return sk.public_key().public_bytes(**X962), sk

    def encaps(self, pk):
        eph = ec.generate_private_key(self.curve())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self.curve(), pk)
        return eph.public_key().public_bytes(**X962), eph.exchange(ec.ECDH(), peer)

    def decaps(self, sk, ct):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(self.curve(), ct)
        return sk.exchange(ec.ECDH(), peer)


class MLKEM:
    def __init__(self, ps):
        self.ps = ps
        k = mlkem.PARAMS[ps][0]
        du, dv = mlkem.PARAMS[ps][3], mlkem.PARAMS[ps][4]
        self.pk_len = 384 * k + 32
        self.ct_len = 32 * (du * k + dv)

    def keygen(self):
        ek, dk = mlkem.keygen_internal(os.urandom(32), os.urandom(32), self.ps)
        return ek, dk

    def encaps(self, pk):
        if not mlkem.ek_check(pk, self.ps):          # FIPS 203 input validation
            raise ValueError('invalid ML-KEM encapsulation key')
        K, c = mlkem.encaps_internal(pk, os.urandom(32), self.ps)
        return c, K

    def decaps(self, sk, ct):
        return mlkem.decaps_internal(sk, ct, self.ps)


class HybridKEM:
    """classical || ML-KEM. The final secret depends on BOTH components."""

    def __init__(self, name, classical, pq):
        self.name, self.c, self.p = name, classical, pq

    def keygen(self):
        pk_c, sk_c = self.c.keygen()
        pk_p, sk_p = self.p.keygen()
        return pk_c + pk_p, (sk_c, sk_p)

    def _combine(self, ss_c, ss_p, ct_c, ct_p, pk_c):
        # PQ secret first, then classical (same ordering idea as X25519MLKEM768).
        # Ciphertexts and the classical public key go into 'info' so the output
        # is bound to the transcript, not just to the raw secrets.
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b'hybrid-kem-v1|' + self.name.encode() + ct_p + ct_c + pk_c
                    ).derive(ss_p + ss_c)

    def encaps(self, pk):
        pk_c, pk_p = pk[:self.c.pk_len], pk[self.c.pk_len:]
        ct_c, ss_c = self.c.encaps(pk_c)
        ct_p, ss_p = self.p.encaps(pk_p)
        return ct_c + ct_p, self._combine(ss_c, ss_p, ct_c, ct_p, pk_c)

    def decaps(self, sk, ct):
        sk_c, sk_p = sk
        ct_c, ct_p = ct[:self.c.ct_len], ct[self.c.ct_len:]
        ss_c = self.c.decaps(sk_c, ct_c)
        ss_p = self.p.decaps(sk_p, ct_p)
        # The receiver needs pk_c for the transcript: recompute it from sk_c.
        if isinstance(sk_c, x25519.X25519PrivateKey):
            pk_c = sk_c.public_key().public_bytes(**RAW)
        else:
            pk_c = sk_c.public_key().public_bytes(**X962)
        return self._combine(ss_c, ss_p, ct_c, ct_p, pk_c)


# ======================================================================
# THE REGISTRY  -  this is what 'crypto-agility' means in code.
# To add or retire an algorithm you change THIS table (or a policy file),
# not the application logic below it.
# ======================================================================
REGISTRY = {
    'ecdh-x25519':           lambda: X25519KEM(),
    'ecdh-p256':             lambda: ECDHKEM(ec.SECP256R1, 65),
    'ecdh-p384':             lambda: ECDHKEM(ec.SECP384R1, 97),
    'mlkem512':              lambda: MLKEM('ML-KEM-512'),
    'mlkem768':              lambda: MLKEM('ML-KEM-768'),
    'mlkem1024':             lambda: MLKEM('ML-KEM-1024'),
    'hybrid-x25519-mlkem768': lambda: HybridKEM('hybrid-x25519-mlkem768',
                                                X25519KEM(), MLKEM('ML-KEM-768')),
    'hybrid-p384-mlkem1024': lambda: HybridKEM('hybrid-p384-mlkem1024',
                                               ECDHKEM(ec.SECP384R1, 97), MLKEM('ML-KEM-1024')),
}
DEPRECATED = {'ecdh-p256': 'quantum-vulnerable: schedule for retirement'}  # policy hook


def get_suite(name):
    if name not in REGISTRY:
        sys.exit(f'unknown suite {name!r}; choices: {", ".join(REGISTRY)}')
    if name in DEPRECATED:
        print(f'[policy warning] {name}: {DEPRECATED[name]}')
    return REGISTRY[name]()


# ======================================================================
# Envelope: KEM -> HKDF -> AES-256-GCM.  AAD binds the suite name.
# ======================================================================
def kdf_to_aes_key(shared_secret, suite_name):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b'envelope-key-v1|' + suite_name.encode()).derive(shared_secret)


def seal(suite_name, recipient_pk, plaintext):
    kem = get_suite(suite_name)
    ct, ss = kem.encaps(recipient_pk)
    key = kdf_to_aes_key(ss, suite_name)
    nonce = os.urandom(12)                       # 96-bit nonce, unique per key
    aad = suite_name.encode()                    # downgrade / confusion protection
    return dict(suite=suite_name, kem_ct=ct, nonce=nonce,
                body=AESGCM(key).encrypt(nonce, plaintext, aad))


def open_(envelope, recipient_sk, allowed=None):
    # Receiver-side policy: only accept suites we explicitly allow.
    # Without this, an attacker could relabel a message to a weaker suite.
    if allowed is not None and envelope['suite'] not in allowed:
        raise PermissionError(f"suite {envelope['suite']!r} not allowed by policy")
    kem = get_suite(envelope['suite'])
    ss = kem.decaps(recipient_sk, envelope['kem_ct'])
    key = kdf_to_aes_key(ss, envelope['suite'])
    return AESGCM(key).decrypt(envelope['nonce'], envelope['body'],
                               envelope['suite'].encode())


# ======================================================================
def cmd_demo(a):
    kem = get_suite(a.suite)
    pk, sk = kem.keygen()
    env = seal(a.suite, pk, a.msg.encode())
    out = open_(env, sk)
    print(f'suite            : {a.suite}')
    print(f'public key       : {len(pk)} bytes')
    print(f'KEM ciphertext   : {len(env["kem_ct"])} bytes')
    print(f'AES-256-GCM body : {len(env["body"])} bytes (plaintext {len(a.msg)} + 16 tag)')
    print(f'decrypted        : {out.decode()!r}')
    assert out == a.msg.encode()


def cmd_tamper(a):
    kem = get_suite(a.suite)
    pk, sk = kem.keygen()
    env = seal(a.suite, pk, b'top secret')
    # attacker changes the claimed suite (downgrade attempt) ...
    forged = dict(env, suite='ecdh-x25519')
    try:
        open_(forged, sk, allowed={a.suite})
    except PermissionError as e:
        print('downgrade attempt rejected :', e)
    # ... or flips one bit of the AES-GCM body
    bad = dict(env, body=bytes([env['body'][0] ^ 1]) + env['body'][1:])
    try:
        open_(bad, sk)
    except InvalidTag:
        print('modified ciphertext rejected: InvalidTag (GCM authentication)')
    # nonce reuse warning (educational)
    key = os.urandom(32)
    n = os.urandom(12)
    c1 = AESGCM(key).encrypt(n, b'A' * 16, None)
    c2 = AESGCM(key).encrypt(n, b'B' * 16, None)
    x = bytes(p ^ q for p, q in zip(c1[:16], c2[:16]))
    print('nonce reuse leaks XOR of plaintexts:', x == bytes(p ^ q for p, q in zip(b'A' * 16, b'B' * 16)))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


def cmd_bench(a):
    print(f'{"suite":26s} {"pk":>6s} {"ct":>6s} {"keygen ms":>10s} {"encaps ms":>10s} '
          f'{"decaps ms":>10s} {"p99 decaps":>10s}')
    for name in REGISTRY:
        kem = REGISTRY[name]()
        kg, en, de = [], [], []
        pk = ct = None
        for _ in range(a.runs):
            t = time.perf_counter(); pk, sk = kem.keygen(); kg.append(time.perf_counter() - t)
            t = time.perf_counter(); ct, ss = kem.encaps(pk); en.append(time.perf_counter() - t)
            t = time.perf_counter(); ss2 = kem.decaps(sk, ct); de.append(time.perf_counter() - t)
            assert ss == ss2
        m = lambda v: statistics.mean(v) * 1000
        print(f'{name:26s} {len(pk):6d} {len(ct):6d} {m(kg):10.3f} {m(en):10.3f} '
              f'{m(de):10.3f} {pct(de, 99) * 1000:10.3f}')
    print('\nNote: ML-KEM rows are PURE PYTHON, so they look slow. Compare SIZES here; '
          'use liboqs/OpenSSL (Lab 3) for real ML-KEM speed.')


def cmd_policy(a):
    """Crypto-agility in action: the algorithm comes from a config file."""
    path = a.file
    if not os.path.exists(path):
        json.dump({'kem_suite': 'hybrid-x25519-mlkem768', 'aead': 'aes-256-gcm'},
                  open(path, 'w'), indent=2)
        print(f'wrote default {path}; edit "kem_suite" and re-run to switch algorithms')
    pol = json.load(open(path))
    print('policy:', pol)
    a.suite, a.msg = pol['kem_suite'], 'policy-driven message'
    cmd_demo(a)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    for n, f in (('demo', cmd_demo), ('tamper', cmd_tamper)):
        p = sub.add_parser(n)
        p.add_argument('--suite', default='hybrid-x25519-mlkem768')
        p.add_argument('--msg', default='hello post-quantum world')
        p.set_defaults(fn=f)
    p = sub.add_parser('bench'); p.add_argument('--runs', type=int, default=20); p.set_defaults(fn=cmd_bench)
    p = sub.add_parser('policy'); p.add_argument('--file', default='policy.json'); p.set_defaults(fn=cmd_policy)
    a = ap.parse_args()
    a.fn(a)
