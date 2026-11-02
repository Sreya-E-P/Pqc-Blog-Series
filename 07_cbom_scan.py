#!/usr/bin/env python3
"""
Lab 7 - Cryptographic inventory (CBOM) scanner

Step 1 of any PQC migration is KNOWING where cryptography is used.
This tool scans a directory and reports:
  * X.509 certificates: signature algorithm, key algorithm/size, expiry
  * PRIVATE KEY files left on disk (a finding by itself)
  * source code: which algorithms/libraries are referenced, file + line
and classifies each item as:
  QUANTUM-VULNERABLE   RSA, DH, ECDH/ECDSA/EdDSA (Shor)
  WEAK-CLASSICAL       MD5, SHA-1, DES/3DES, RC4, AES-128 (long-term), ECB
  PQC                  ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon/FN-DSA
  OK                   AES-256, SHA-256/384/512, SHA-3, HKDF, ChaCha20
  REVIEW               pickle of keys, 'simulat', hard-coded secrets patterns

Output: a table on screen + cbom.json (simplified CycloneDX-style cryptographic assets).

    python3 07_cbom_scan.py /path/to/project
    OPENSSL=/path/to/openssl python3 07_cbom_scan.py ./pki      # to parse PQ certs
"""
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

OPENSSL = os.environ.get('OPENSSL', 'openssl')
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'build', 'dist'}
CODE_EXT = {'.py', '.c', '.cc', '.cpp', '.h', '.hpp', '.java', '.js', '.ts', '.go', '.rs', '.sh',
            '.cnf', '.yaml', '.yml', '.json', '.toml', '.conf', '.edl'}

# (regex, label, status, note)
RULES = [
    (r'\bRSA\b|rsa\.generate|RSA_generate|rsaEncryption|PKCS1v15|OAEP', 'RSA', 'QUANTUM-VULNERABLE', 'Shor breaks RSA'),
    (r'\bECDSA\b|ec\.ECDSA|SECP\d+R1|secp\d+r1|prime256v1|P-256|P-384|P-521', 'ECDSA/EC curves', 'QUANTUM-VULNERABLE', 'Shor breaks ECC'),
    (r'\bECDH\b|ec\.ECDH|X25519|x25519|X448', 'ECDH/X25519', 'QUANTUM-VULNERABLE', 'key exchange: HNDL risk, migrate first'),
    (r'Ed25519|ed25519|EdDSA', 'EdDSA', 'QUANTUM-VULNERABLE', 'Shor breaks EdDSA'),
    (r'\bDiffie|\bDH\b|dh\.generate', 'DH', 'QUANTUM-VULNERABLE', 'Shor breaks DH'),
    (r'hashlib\.md5|\bMD5\b|md5\(', 'MD5', 'WEAK-CLASSICAL', 'broken hash'),
    (r'hashlib\.sha1|\bSHA-?1\b|sha1\(', 'SHA-1', 'WEAK-CLASSICAL', 'collision-broken'),
    (r'\b3?DES\b|DES3|TripleDES', 'DES/3DES', 'WEAK-CLASSICAL', 'obsolete cipher'),
    (r'\bRC4\b|ARC4', 'RC4', 'WEAK-CLASSICAL', 'broken cipher'),
    (r'AES[-_]?128|aes_128|AES128', 'AES-128', 'WEAK-CLASSICAL', 'ok today; prefer AES-256 for long-term (Grover)'),
    (r'MODE_ECB|modes\.ECB|AES-ECB|aes_ecb', 'ECB mode', 'WEAK-CLASSICAL', 'leaks patterns'),
    (r'ML-?KEM|MLKEM|Kyber|kyber', 'ML-KEM/Kyber', 'PQC', 'post-quantum KEM'),
    (r'ML-?DSA|MLDSA|Dilithium|dilithium', 'ML-DSA/Dilithium', 'PQC', 'post-quantum signature'),
    (r'SLH-?DSA|SPHINCS', 'SLH-DSA/SPHINCS+', 'PQC', 'hash-based signature'),
    (r'Falcon|FN-DSA', 'Falcon/FN-DSA', 'PQC', 'compact PQ signature'),
    (r'\boqs\b|liboqs', 'liboqs', 'PQC', 'PQC library'),
    (r'AES[-_]?256|aes_256|AESGCM|AES-GCM|ChaCha20', 'AES-256/AEAD', 'OK', 'quantum-safe symmetric'),
    (r'SHA-?(256|384|512)|sha(256|384|512)|SHA3|sha3_', 'SHA-2/SHA-3', 'OK', 'fine'),
    (r'HKDF|hkdf|PBKDF2|pbkdf2|scrypt|argon2', 'KDF', 'OK', 'key derivation'),
    (r'pickle\.(dump|load)', 'pickle', 'REVIEW', 'pickle is unsafe to load and often used to persist keys'),
    (r'simulat', 'simulation', 'REVIEW', 'simulated crypto must be fail-closed, never silent'),
    (r'(password|passwd|secret|api_?key)\s*=\s*[\'"][^\'"]{6,}[\'"]', 'hard-coded secret', 'REVIEW', 'secrets belong in a vault'),
]
COMPILED = [(re.compile(p, re.I if label in ('simulation',) else 0), label, st, note)
            for p, label, st, note in RULES]


def classify_algo(name):
    n = name.lower()
    if any(x in n for x in ('ml-dsa', 'mldsa', 'slh-dsa', 'falcon', 'dilithium', 'sphincs', 'ml-kem')):
        return 'PQC'
    if any(x in n for x in ('rsa', 'ec', 'ed25519', 'ed448', 'dsa', 'x25519')):
        return 'QUANTUM-VULNERABLE'
    return 'REVIEW'


def scan_cert(path, text):
    out = []
    for m in re.finditer(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', text, re.S):
        pem = m.group(0)
        r = subprocess.run([OPENSSL, 'x509', '-noout', '-text', '-enddate'], input=pem.encode(),
                           capture_output=True)
        t = r.stdout.decode(errors='replace')
        if not t:
            out.append(dict(file=path, kind='certificate', algo='unparseable', status='REVIEW',
                            detail=r.stderr.decode(errors='replace')[:80]))
            continue
        sig = re.search(r'Signature Algorithm:\s*(\S+)', t)
        pk = re.search(r'Public Key Algorithm:\s*(\S+)', t)
        bits = re.search(r'Public-Key:\s*\((\d+) bit\)', t)
        end = re.search(r'notAfter=(.*)', t)
        subj = re.search(r'Subject:\s*(.*)', t)
        sig_a, pk_a = (sig.group(1) if sig else '?'), (pk.group(1) if pk else '?')
        status = 'PQC' if classify_algo(sig_a) == 'PQC' and classify_algo(pk_a) == 'PQC' else \
                 classify_algo(sig_a) if classify_algo(sig_a) != 'REVIEW' else classify_algo(pk_a)
        out.append(dict(file=path, kind='certificate', algo=f'sig={sig_a} key={pk_a}'
                        + (f' ({bits.group(1)} bit)' if bits else ''),
                        status=status, detail=f'{subj.group(1).strip() if subj else ""}; expires {end.group(1).strip() if end else "?"}'))
    return out


def scan_file(path):
    findings = []
    try:
        raw = open(path, 'rb').read()
    except OSError:
        return findings
    if b'\x00' in raw[:2048]:
        return findings                      # binary
    text = raw.decode(errors='replace')
    if 'BEGIN CERTIFICATE' in text:
        findings += scan_cert(path, text)
    m = re.search(r'-----BEGIN ((?:[A-Z0-9 ]+ )?PRIVATE KEY)-----', text)
    if m:
        findings.append(dict(file=path, kind='private-key-file', algo=m.group(1), status='REVIEW',
                             detail='PRIVATE KEY on disk: confirm it is not committed, encrypted at rest, access-controlled'))
    if os.path.splitext(path)[1].lower() in CODE_EXT:
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 400:
                continue
            for rx, label, status, note in COMPILED:
                if rx.search(line):
                    findings.append(dict(file=path, line=i, kind='code', algo=label, status=status,
                                         detail=note, snippet=line.strip()[:100]))
    return findings


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    findings = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            findings += scan_file(os.path.join(d, f))

    by_status = Counter(f['status'] for f in findings)
    by_algo = defaultdict(lambda: Counter())
    for f in findings:
        by_algo[f['algo']][f['status']] += 1

    print(f'Scanned {root}: {len(findings)} findings\n')
    print('=== Summary by status ===')
    for st in ('QUANTUM-VULNERABLE', 'WEAK-CLASSICAL', 'REVIEW', 'PQC', 'OK'):
        print(f'  {st:20s} {by_status.get(st, 0):5d}')

    print('\n=== Summary by algorithm ===')
    for algo, c in sorted(by_algo.items(), key=lambda kv: -sum(kv[1].values())):
        st = next(iter(c))
        print(f'  {algo[:60]:60s} {st:20s} x{sum(c.values())}')

    print('\n=== Certificates and key files ===')
    for f in findings:
        if f['kind'] in ('certificate', 'private-key-file'):
            print(f'  [{f["status"]:18s}] {f["kind"]:16s} {os.path.relpath(f["file"], root)}\n'
                  f'      {f["algo"]}  | {f["detail"]}')

    print('\n=== REVIEW items (code) ===')
    for f in findings:
        if f['status'] == 'REVIEW' and f['kind'] == 'code':
            print(f'  {os.path.relpath(f["file"], root)}:{f["line"]}  {f["algo"]}: {f["snippet"]}')

    cbom = {
        'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
        'metadata': {'component': {'type': 'application', 'name': os.path.basename(os.path.abspath(root))}},
        'components': [
            {'type': 'cryptographic-asset', 'name': f['algo'],
             'cryptoProperties': {'assetType': 'certificate' if f['kind'] == 'certificate' else 'algorithm',
                                  'quantumStatus': f['status']},
             'evidence': {'occurrences': [{'location': f['file'], 'line': f.get('line')}]},
             'description': f['detail']}
            for f in findings],
    }
    json.dump(cbom, open('cbom.json', 'w'), indent=2)
    print(f'\nWrote cbom.json ({len(cbom["components"])} components)')
    vuln = by_status.get('QUANTUM-VULNERABLE', 0)
    if vuln:
        print(f'\nPRIORITY: {vuln} quantum-vulnerable references. Migrate KEY EXCHANGE first '
              f'(harvest-now-decrypt-later), then signatures.')


if __name__ == '__main__':
    main()
