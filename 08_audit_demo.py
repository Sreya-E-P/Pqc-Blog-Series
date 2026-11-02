#!/usr/bin/env python3
"""
Lab 8 - Auditing a post-quantum project: prove what is REAL and what is SIMULATED

Run it against your ThreatShield source (the folder that contains ts_crypto/):
    python3 08_audit_demo.py /path/to/ThreatShield/backend/src
(It runs in a temporary directory so it does not create key_backups/ in your repo.)

It answers five questions with evidence, not opinion:
  Q1  Is the real liboqs library actually in use, or the fallback simulation?
  Q2  Which object performs the 'PQ signature', and is it a real signature scheme?
  Q3  Can someone with ONLY the public key verify a PQ signature?
  Q4  In simulation mode, can an attacker with ONLY the public key recover the KEM secret?
  Q5  Are private keys written to disk in the clear?
"""
import os
import pickle
import sys
import tempfile

src = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else None
if not src or not os.path.isdir(os.path.join(src, 'ts_crypto')):
    sys.exit('usage: python3 08_audit_demo.py /path/to/src   (folder containing ts_crypto/)')

sys.path.insert(0, src)
work = tempfile.mkdtemp(prefix='audit_')
os.chdir(work)                                   # key_backups/ will be created HERE, not in your repo
os.environ['KEY_BACKUP_DIR'] = os.path.join(work, 'key_backups')

import logging
logging.disable(logging.CRITICAL)
from ts_crypto import hybrid_pqc as hp           # noqa: E402

PASS, FAIL = 'OK  ', 'FLAW'


def line(tag, msg):
    print(f'  [{tag}] {msg}')


crypto = hp.HybridCryptoSystem(security_level='high', enable_hardware_accel=False)
kp = crypto.generate_keypair(backup=True)
msg = b'critical firmware update'

print('\nQ1  Is real liboqs in use?')
line(PASS if hp.PQC_AVAILABLE else FAIL, f'PQC_AVAILABLE = {hp.PQC_AVAILABLE}  '
     f'({"oqs imported" if hp.PQC_AVAILABLE else "oqs missing: EVERYTHING below runs on the simulation"})')
ct, ss = crypto.pqc.encapsulate(kp.pq_public)
stats = crypto.pqc.get_stats()
used_real_kem = stats.get('pqc_encapsulations', 0) > 0
line(PASS if used_real_kem else FAIL, f'KEM path actually used: '
     f'{"real liboqs (pqc_encapsulations)" if used_real_kem else "SIMULATED (simulated_encapsulations)"}  stats={stats}')
print('      Why this matters: the code catches every oqs error and silently falls back. A wrong algorithm name or a '
      'liboqs version change gives you fake crypto with no crash.')

print('\nQ2  Which object does the PQ signature, and is it a signature scheme?')
alg = crypto.pqc.algorithm
line(FAIL if alg.alg_type != 'Signature' else PASS,
     f'self.pqc was built for {alg.value!r} (type={alg.alg_type}). Real signing is only attempted when '
     f'type == "Signature", so the "{crypto.signature_algorithm.value}" label is never used for signing.')
sig_pkg = crypto.sign(msg, kp.key_id)
after = crypto.pqc.get_stats()
sim = after.get('simulated_signatures', 0)
line(FAIL if sim else PASS, f'after one sign(): simulated_signatures = {sim}, '
     f'pqc signature bytes = {len(__import__("base64").b64decode(sig_pkg["pq_signature"]))} '
     f'(a real {crypto.signature_algorithm.value} signature is about {"4.6" if "5" in crypto.signature_algorithm.value else "3.3"} KB)')

print('\nQ3  Can someone with only the PUBLIC key verify it?')
pq_sig = __import__('base64').b64decode(sig_pkg['pq_signature'])
try:
    crypto.pqc.verify(msg, pq_sig, kp.pq_public)           # public key only, like a real verifier
    line(PASS, 'verified with the public key alone')
except ValueError as e:
    line(FAIL, f'verification needs the PRIVATE key: "{e}". A signature that only the key owner can check '
               'is a MAC, not a digital signature (no non-repudiation, no third-party verification).')

print('\nQ4  Simulation mode: can an attacker holding only the public key recover the KEM shared secret?')
sim_ct, sim_ss = crypto.pqc._sim_encapsulate(kp.pq_public)
attacker_ss = crypto.pqc._sim_decapsulate(kp.pq_public, sim_ct)      # note: NO private key used
line(FAIL if attacker_ss == sim_ss else PASS,
     f'attacker recovered the secret using only the public key: {attacker_ss == sim_ss}. '
     'The wrap key is HKDF(public_key), and public keys are public.')

print('\nQ5  Are private keys stored in the clear?')
files = os.listdir(crypto._key_backup_dir)
blob = open(os.path.join(crypto._key_backup_dir, files[0]), 'rb').read()
loaded = pickle.loads(blob)
line(FAIL, f'{len(files)} backup file(s) in key_backups/. Loading one with pickle exposed pq_private '
           f'({len(loaded.pq_private)} B) and classical_private ({len(loaded.classical_private)} B) with NO password. '
           'Also: pickle.loads on untrusted data is arbitrary code execution.')

print('\nWHAT IS REAL: ECDSA-P384 signing, ECDH-P384, HKDF, AES-256-GCM with random 96-bit nonces.')
print('WHAT IS NOT: the PQ signature (always an HMAC), the fallback KEM, the "QRNG", key storage, HSM (none).')
print(f'\n(Temporary files in {work} - safe to delete.)')
