#!/usr/bin/env python3
"""
Lab 5 - HSM integration with PKCS#11 (SoftHSM2 as a stand-in HSM)

What you will do:
  setup   create a private SoftHSM token + keys that never leave it
  sign    ECDSA P-256 signing INSIDE the HSM, verified outside with 'cryptography'
  wrap    protect a POST-QUANTUM private key (ML-DSA-65) under an AES-256 KEK that
          lives in the HSM (AES-256-GCM executed by the HSM), then use it
  rotate  re-wrap the PQ key under a new KEK (key rotation / crypto-agility)
  probe   list which mechanisms this HSM supports (is native PQC available?)

THE HONEST ARCHITECTURE (say this in the interview):
  Most deployed HSMs/PKCS#11 modules cannot do ML-DSA/ML-KEM natively yet
  (PKCS#11 v3.2 added the mechanisms; vendors are catching up). Until they do, a
  common interim pattern is: the PQ private key is stored ENCRYPTED under a
  non-extractable AES-256 key inside the HSM, and unwrapped into process memory
  only when needed. That protects the key at rest and in backups; it does NOT
  protect it while in use. Native HSM support closes that gap.

Needs: softhsm2, python-pkcs11 (pip install python-pkcs11), OpenSSL >= 3.5 for ML-DSA.
    OPENSSL=/path/to/openssl python3 05_hsm_lab.py setup
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HSM_DIR = os.path.join(os.getcwd(), 'hsm')
os.environ['SOFTHSM2_CONF'] = os.path.join(HSM_DIR, 'softhsm2.conf')   # BEFORE loading the module

import pkcs11                                   # noqa: E402
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass   # noqa: E402
from pkcs11.mechanisms import GCMParams                         # noqa: E402

OPENSSL = os.environ.get('OPENSSL', 'openssl')
TOKEN, SO_PIN, USER_PIN = 'labtoken', '12345678', '1234'
WRAPPED = os.path.join(HSM_DIR, 'pq_sk.wrapped.json')
PQ_PUB = os.path.join(HSM_DIR, 'pq_pub.pem')
CANDIDATES = ['/usr/lib/softhsm/libsofthsm2.so', '/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
              '/usr/local/lib/softhsm/libsofthsm2.so', '/usr/lib64/pkcs11/libsofthsm2.so']


def module_path():
    p = os.environ.get('PKCS11_MODULE')
    if p:
        return p
    for c in CANDIDATES:
        if os.path.exists(c):
            return c
    sys.exit('SoftHSM module not found. Install softhsm2 or set PKCS11_MODULE=/path/to/libsofthsm2.so')


def open_session():
    lib = pkcs11.lib(module_path())
    return lib.get_token(token_label=TOKEN).open(user_pin=USER_PIN, rw=True)


def find_key(session, label, klass):
    for o in session.get_objects({Attribute.LABEL: label, Attribute.CLASS: klass}):
        return o
    sys.exit(f'object {label!r} not found - run: python3 05_hsm_lab.py setup')


# ------------------------------------------------------------------ setup
def cmd_setup(a):
    os.makedirs(os.path.join(HSM_DIR, 'tokens'), exist_ok=True)
    with open(os.environ['SOFTHSM2_CONF'], 'w') as f:
        f.write(f'directories.tokendir = {HSM_DIR}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n')
    if not shutil.which('softhsm2-util'):
        sys.exit('softhsm2-util not found. Install it:  sudo apt install softhsm2')
    subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', TOKEN,
                    '--so-pin', SO_PIN, '--pin', USER_PIN], check=True, capture_output=True)
    s = open_session()
    # ECDSA signing key pair: private key is SENSITIVE and NOT extractable
    from pkcs11.util.ec import encode_named_curve_parameters
    params = s.create_domain_parameters(
        KeyType.EC, {Attribute.EC_PARAMS: encode_named_curve_parameters('secp256r1')}, local=True)
    params.generate_keypair(store=True, label='sign-key',
                            private_template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                                              Attribute.SIGN: True, Attribute.TOKEN: True},
                            public_template={Attribute.VERIFY: True, Attribute.TOKEN: True})
    # AES-256 key-encryption key (KEK) for protecting PQ private keys
    s.generate_key(KeyType.AES, 256, store=True, label='pq-kek-v1',
                   template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                             Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: True})
    print(f'token {TOKEN!r} ready in {HSM_DIR}')
    print('objects:', [(o[Attribute.LABEL], getattr(o[Attribute.CLASS], 'name', o[Attribute.CLASS]))
                       for o in s.get_objects()])


# ------------------------------------------------------------------ probe
def cmd_probe(a):
    s = open_session()
    mechs = s.token.slot.get_mechanisms()
    names = sorted(getattr(m, 'name', str(m)) for m in mechs)
    pq = [n for n in names if any(x in n for x in ('ML_KEM', 'ML_DSA', 'SLH_DSA', 'KYBER', 'DILITHIUM'))]
    print(f'{len(names)} mechanisms. AES_GCM: {"AES_GCM" in names}   ECDSA: {"ECDSA" in names}')
    print('native PQC mechanisms:', pq if pq else 'NONE (typical for current HSMs/SoftHSM; PKCS#11 v3.2 adds them)')
    print('\nIn the interview: "Before choosing an architecture I probe the module for CKM_ML_KEM / '
          'CKM_ML_DSA / CKM_SLH_DSA. If absent, keys are wrapped under an HSM-resident AES-256 KEK."')


# ------------------------------------------------------------------ sign (classical, in HSM)
def cmd_sign(a):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    s = open_session()
    priv = find_key(s, 'sign-key', ObjectClass.PRIVATE_KEY)
    pub = find_key(s, 'sign-key', ObjectClass.PUBLIC_KEY)
    msg = a.msg.encode()
    digest = hashlib.sha256(msg).digest()
    raw = priv.sign(digest, mechanism=Mechanism.ECDSA)           # computed inside the HSM
    r, sv = int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')
    point = bytes(pub[Attribute.EC_POINT])[2:]                    # strip DER OCTET STRING header
    pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    pk.verify(encode_dss_signature(r, sv), msg, ec.ECDSA(hashes.SHA256()))
    print(f'HSM signature ({len(raw)} bytes) verified OUTSIDE the HSM with the exported public key')
    try:
        bad = encode_dss_signature(r, (sv + 1) % (1 << 256))
        pk.verify(bad, msg, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print('a modified signature is rejected: OK')
    try:
        _ = priv[Attribute.VALUE]
        print('!! private key material was readable (this would be a misconfiguration)')
    except Exception as e:
        print(f'private key extraction attempt blocked: {type(e).__name__}')
    print(f'private key flags: sensitive={bool(priv[Attribute.SENSITIVE])} '
          f'extractable={bool(priv[Attribute.EXTRACTABLE])}')


# ------------------------------------------------------------------ wrap (PQ key protected by HSM KEK)
def gcm_encrypt(kek, iv, aad, data):
    return kek.encrypt(data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(iv, aad, 128))


def gcm_decrypt(kek, iv, aad, data):
    return kek.decrypt(data, mechanism=Mechanism.AES_GCM, mechanism_param=GCMParams(iv, aad, 128))


def secure_delete(path):
    try:
        n = os.path.getsize(path)
        with open(path, 'r+b') as f:
            f.write(os.urandom(n)); f.flush(); os.fsync(f.fileno())
        os.remove(path)
    except FileNotFoundError:
        pass


def run(cmd):
    return subprocess.run(cmd, check=True, capture_output=True)


def cmd_wrap(a):
    s = open_session()
    kek = find_key(s, a.kek, ObjectClass.SECRET_KEY)
    tmp = os.path.join(HSM_DIR, 'tmp_pq_sk.pem')
    run([OPENSSL, 'genpkey', '-algorithm', 'ML-DSA-65', '-out', tmp])
    run([OPENSSL, 'pkey', '-in', tmp, '-pubout', '-out', PQ_PUB])
    secret = open(tmp, 'rb').read()
    iv = os.urandom(12)                                           # 96-bit, unique per encryption
    aad = f'pq-sk|ML-DSA-65|kek={a.kek}|v1'.encode()              # binds blob to algorithm + KEK name
    ct = gcm_encrypt(kek, iv, aad, secret)                        # AES-256-GCM executed by the HSM
    json.dump({'kek': a.kek, 'iv': iv.hex(), 'aad': aad.decode(), 'ct': ct.hex()}, open(WRAPPED, 'w'), indent=2)
    secure_delete(tmp)
    print(f'ML-DSA-65 private key ({len(secret)} B PEM) -> wrapped blob ({len(ct)} B) under HSM key {a.kek!r}')
    print(f'plaintext key file destroyed; only {WRAPPED} remains on disk')

    # ---- use it: unwrap into memory, sign, destroy
    blob = json.load(open(WRAPPED))
    pt = gcm_decrypt(find_key(s, blob['kek'], ObjectClass.SECRET_KEY), bytes.fromhex(blob['iv']),
                     blob['aad'].encode(), bytes.fromhex(blob['ct']))
    work = '/dev/shm' if os.path.isdir('/dev/shm') else HSM_DIR
    key_tmp, msg_f, sig_f = (os.path.join(work, n) for n in ('pq_tmp.key', 'pq_msg.bin', 'pq_sig.bin'))
    open(key_tmp, 'wb').write(pt); os.chmod(key_tmp, 0o600)
    open(msg_f, 'wb').write(b'firmware-image-v1.2.3')
    run([OPENSSL, 'pkeyutl', '-sign', '-inkey', key_tmp, '-rawin', '-in', msg_f, '-out', sig_f])
    secure_delete(key_tmp)
    ok = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-inkey', PQ_PUB, '-rawin', '-in', msg_f,
                         '-sigfile', sig_f], capture_output=True)
    print(f'ML-DSA-65 signature {os.path.getsize(sig_f)} B -> verify: {ok.stdout.decode().strip() or ok.stderr.decode().strip()}')
    for f in (msg_f, sig_f):
        secure_delete(f)

    # ---- tamper tests
    bad = bytearray(bytes.fromhex(blob['ct'])); bad[10] ^= 1
    for label, ctx, aad2 in (('flipped ciphertext bit', bytes(bad), blob['aad'].encode()),
                             ('wrong AAD (blob swapped to another purpose)', bytes.fromhex(blob['ct']), b'other')):
        try:
            gcm_decrypt(find_key(s, blob['kek'], ObjectClass.SECRET_KEY), bytes.fromhex(blob['iv']), aad2, ctx)
            print(f'!! {label}: NOT detected')
        except Exception as e:
            print(f'{label}: rejected ({type(e).__name__})')


# ------------------------------------------------------------------ rotate
def cmd_rotate(a):
    s = open_session()
    blob = json.load(open(WRAPPED))
    old = find_key(s, blob['kek'], ObjectClass.SECRET_KEY)
    new_label = a.new
    if not list(s.get_objects({Attribute.LABEL: new_label, Attribute.CLASS: ObjectClass.SECRET_KEY})):
        s.generate_key(KeyType.AES, 256, store=True, label=new_label,
                       template={Attribute.SENSITIVE: True, Attribute.EXTRACTABLE: False,
                                 Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: True})
    new = find_key(s, new_label, ObjectClass.SECRET_KEY)
    pt = gcm_decrypt(old, bytes.fromhex(blob['iv']), blob['aad'].encode(), bytes.fromhex(blob['ct']))
    iv = os.urandom(12)
    aad = blob['aad'].replace(f"kek={blob['kek']}", f'kek={new_label}').encode()
    ct = gcm_encrypt(new, iv, aad, pt)
    json.dump({'kek': new_label, 'iv': iv.hex(), 'aad': aad.decode(), 'ct': ct.hex()}, open(WRAPPED, 'w'), indent=2)
    print(f're-wrapped under {new_label!r} (fresh IV). Old KEK {blob["kek"]!r} can now be retired.')
    print('This is how you rotate protection keys, or move to a new algorithm, without touching the PQ key itself.')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('setup').set_defaults(fn=cmd_setup)
    sub.add_parser('probe').set_defaults(fn=cmd_probe)
    p = sub.add_parser('sign'); p.add_argument('--msg', default='transaction #1042'); p.set_defaults(fn=cmd_sign)
    p = sub.add_parser('wrap'); p.add_argument('--kek', default='pq-kek-v1'); p.set_defaults(fn=cmd_wrap)
    p = sub.add_parser('rotate'); p.add_argument('--new', default='pq-kek-v2'); p.set_defaults(fn=cmd_rotate)
    a = ap.parse_args()
    a.fn(a)
