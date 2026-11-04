#!/usr/bin/env python3
"""
Lab 13 (Azure series, Post 2) - Try ML-DSA in Azure Key Vault (preview) and verify it OUTSIDE Azure.

BACKGROUND
  Key Vault data-plane API 2026-07-01-preview defines a new key type 'AKP' (Algorithm Key Pair,
  'AKP-HSM' for HSM-backed) carrying ML-DSA-44/65/87. SDKs (e.g. .NET Azure.Security.KeyVault.Keys
  4.11.0-beta.x) already expose it, but a public report from October 2026 says the live service
  still rejected kty=AKP on premium vaults in some regions and returned a 500 on Managed HSM.
  So this lab is written to be HONEST EITHER WAY:
     * if your vault supports it -> create, sign, verify with OpenSSL, tamper-test, delete
     * if not               -> print the service's exact answer and exit non-zero (fail-closed)

ASSUMPTIONS I COULD NOT TEST (check them against a real response / current docs):
  1. request body for create: {"kty": "AKP", "alg": "ML-DSA-65", "key_ops": ["sign","verify"]}
  2. the returned JWK carries the raw public key base64url-encoded in the field "pub"
  3. sign takes {"alg": "ML-DSA-65", "value": <base64url MESSAGE>} (pure ML-DSA, not a digest)
  If any of these differ, the error message printed below tells you what to change.

Needs:  pip install azure-identity requests    and   OpenSSL >= 3.5 (ML-DSA verify)
Auth :  `az login` (DefaultAzureCredential). Your identity needs key create/sign/delete rights
        (e.g. 'Key Vault Crypto Officer' on an RBAC vault).

Usage:
    OPENSSL=/path/to/openssl python3 13_keyvault_mldsa.py --vault https://myvault.vault.azure.net
    python3 13_keyvault_mldsa.py --vault https://myvault.vault.azure.net --alg ML-DSA-87 --kty AKP-HSM
Use a THROWAWAY vault: the script deletes its test key, but soft-delete keeps it recoverable.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

import requests
from azure.identity import DefaultAzureCredential

API = '2026-07-01-preview'
OPENSSL = os.environ.get('OPENSSL', 'openssl')
# NIST OIDs 2.16.840.1.101.3.4.3.{17,18,19}
OID = {'ML-DSA-44': '608648016503040311', 'ML-DSA-65': '608648016503040312',
       'ML-DSA-87': '608648016503040313'}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def der(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + ln + body


def spki(alg, raw_pub):
    """Wrap a raw ML-DSA public key into a SubjectPublicKeyInfo so OpenSSL can read it."""
    algid = der(0x30, der(0x06, bytes.fromhex(OID[alg])))
    return der(0x30, algid + der(0x03, b'\x00' + raw_pub))


def fail(msg, r=None):
    print(f'\nRESULT: NOT AVAILABLE / FAILED  ->  {msg}')
    if r is not None:
        print(f'  HTTP {r.status_code}\n  {r.text[:600]}')
    print('\nFail-closed: do NOT fall back to a classical key silently. Record this answer, the region,'
          '\nthe vault SKU and today\'s date; that IS the finding for the blog post.')
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vault', required=True, help='https://<name>.vault.azure.net or the Managed HSM URL')
    ap.add_argument('--alg', default='ML-DSA-65', choices=list(OID))
    ap.add_argument('--kty', default='AKP', choices=['AKP', 'AKP-HSM'])
    ap.add_argument('--keep', action='store_true', help='do not delete the test key at the end')
    a = ap.parse_args()
    vault = a.vault.rstrip('/')
    name = f'pqc-lab-{int(time.time())}'

    scope = 'https://managedhsm.azure.net/.default' if 'managedhsm' in vault else 'https://vault.azure.net/.default'
    tok = DefaultAzureCredential().get_token(scope).token
    H = {'Authorization': f'Bearer {tok}', 'Content-Type': 'application/json'}
    q = {'api-version': API}

    print(f'vault {vault} | api {API} | kty {a.kty} | alg {a.alg}\n')

    # 1) create
    r = requests.post(f'{vault}/keys/{name}/create', params=q, headers=H, timeout=60,
                      json={'kty': a.kty, 'alg': a.alg, 'key_ops': ['sign', 'verify']})
    if r.status_code >= 300:
        fail('key creation was refused', r)
    jwk = r.json()['key']
    kid = jwk['kid']
    print(f'created key: {kid}')
    if 'pub' not in jwk:
        fail('response has no "pub" field: assumption 2 is wrong, print the JWK and adapt', r)
    raw_pub = unb64u(jwk['pub'])
    print(f'public key: {len(raw_pub)} bytes (expected 1312 / 1952 / 2592 for 44 / 65 / 87)')

    try:
        # 2) sign inside Key Vault
        msg = b'firmware-image-v1.2.3'
        r = requests.post(f'{kid}/sign', params=q, headers=H, timeout=60,
                          json={'alg': a.alg, 'value': b64u(msg)})
        if r.status_code >= 300:
            fail('sign was refused', r)
        sig = unb64u(r.json()['value'])
        print(f'signature from Key Vault: {len(sig)} bytes (ML-DSA-65 should be 3309)')

        # 3) verify OUTSIDE Azure with OpenSSL, using only the public key
        with tempfile.TemporaryDirectory() as d:
            pub_f, msg_f, sig_f = (os.path.join(d, n) for n in ('pub.der', 'msg', 'sig'))
            open(pub_f, 'wb').write(spki(a.alg, raw_pub))
            open(msg_f, 'wb').write(msg)
            open(sig_f, 'wb').write(sig)

            def verify(path):
                p = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', pub_f,
                                    '-rawin', '-in', path, '-sigfile', sig_f], capture_output=True)
                return p.returncode == 0, (p.stdout + p.stderr).decode().strip()

            ok, out = verify(msg_f)
            print(f'OpenSSL verify (public key only): {"VALID" if ok else "INVALID"}  {out}')
            bad_f = os.path.join(d, 'bad')
            open(bad_f, 'wb').write(msg + b'x')
            ok2, _ = verify(bad_f)
            print(f'tampered message rejected: {not ok2}')
            if not ok or ok2:
                fail('verification result is wrong: check assumption 3 (message vs digest, context string)')
        print('\nRESULT: ML-DSA sign in Key Vault + independent verify = WORKS on this vault today.')
    finally:
        if not a.keep:
            d = requests.delete(f'{vault}/keys/{name}', params=q, headers=H, timeout=60)
            print(f'cleanup: delete -> HTTP {d.status_code} (soft-delete may keep it recoverable)')


if __name__ == '__main__':
    main()
