#!/usr/bin/env python3
"""
Lab 3 - Post-quantum TLS 1.3

Runs real TLS 1.3 handshakes with OpenSSL (>= 3.5) in several configurations and
measures: bytes on the wire (via a counting proxy), time, negotiated group and
signature type, plus a per-message size breakdown (ClientHello, Certificate, ...).

Prerequisite: run 02_pki_lab.sh first (creates ./pki/...).

Usage:
    OPENSSL=/path/to/openssl python3 03_tls_lab.py bench   --runs 30
    OPENSSL=/path/to/openssl python3 03_tls_lab.py msgs
    OPENSSL=/path/to/openssl python3 03_tls_lab.py dual

Timing note: every handshake launches a new `openssl s_client` process, so absolute
times include process start-up. Compare scenarios RELATIVE to each other and to the
printed baseline. Byte counts are exact.
"""
import argparse
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time

OPENSSL = os.environ.get('OPENSSL', 'openssl')
PKI = os.environ.get('PKI', 'pki')
HOST = '127.0.0.1'
SERVER_PORT, PROXY_PORT = 14433, 14434

# name, key-exchange group(s), PKI chain
SCENARIOS = [
    ('A classical (X25519 + ECDSA)',        'X25519',         'classical'),
    ('B hybrid KEX + ECDSA certs',          'X25519MLKEM768', 'classical'),
    ('C hybrid KEX + ML-DSA certs',         'X25519MLKEM768', 'pq'),
    ('D pure ML-KEM-768 + ML-DSA certs',    'MLKEM768',       'pq'),
    ('E hybrid KEX + SLH-DSA-rooted PKI',   'X25519MLKEM768', 'slhroot'),
]


# ------------------------------------------------------------------ helpers
def start_server(chain, groups, extra=None):
    # refuse to run if something (e.g. a stale s_server) already owns the port
    try:
        socket.create_connection((HOST, SERVER_PORT), timeout=0.2).close()
        raise RuntimeError(f'port {SERVER_PORT} already in use - run: pkill -x openssl')
    except (ConnectionRefusedError, socket.timeout):
        pass
    d = f'{PKI}/{chain}'
    cmd = [OPENSSL, 's_server', '-accept', str(SERVER_PORT), '-tls1_3',
           '-cert', f'{d}/leaf.crt', '-key', f'{d}/leaf.key', '-cert_chain', f'{d}/int.crt',
           '-groups', groups, '-num_tickets', '0', '-www', '-quiet']
    if extra:
        cmd += extra
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):                      # wait until the port accepts
        try:
            socket.create_connection((HOST, SERVER_PORT), timeout=0.2).close()
            return p
        except OSError:
            time.sleep(0.05)
    p.kill()
    raise RuntimeError('server did not start: check OPENSSL path/version and ' + chain)


class CountingProxy(threading.Thread):
    """Forwards client<->server and records bytes in each direction per connection."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stats, self.stop = [], False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((HOST, PROXY_PORT))
        self.sock.listen(16)

    def _pump(self, a, b, box, idx):
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                box[idx] += len(data)
                b.sendall(data)
        except OSError:
            pass
        finally:
            try:
                b.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle(self, c):
        s = socket.create_connection((HOST, SERVER_PORT))
        box = [0, 0]
        t1 = threading.Thread(target=self._pump, args=(c, s, box, 0))
        t2 = threading.Thread(target=self._pump, args=(s, c, box, 1))
        t1.start(); t2.start(); t1.join(); t2.join()
        c.close(); s.close()
        self.stats.append(tuple(box))

    def run(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()


def client_cmd(port, groups, chain, extra=None, msg=False):
    cmd = [OPENSSL, 's_client', '-connect', f'{HOST}:{port}', '-tls1_3', '-groups', groups,
           '-CAfile', f'{PKI}/{chain}/root.crt', '-verify_hostname', 'localhost',
           '-verify_return_error', '-servername', 'localhost']
    cmd += ['-msg'] if msg else ['-brief']
    if extra:
        cmd += extra
    return cmd


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p / 100))]


def parse_brief(text):
    out = {}
    for key, pat in (('group', r'(?:Negotiated TLS1\.3 group|Peer Temp Key):\s*([^\s,]+)'),
                     ('sig', r'Signature type:\s*(\S+)'),
                     ('verify', r'Verification:\s*(\S+)'),
                     ('cipher', r'Ciphersuite:\s*(\S+)')):
        m = re.search(pat, text)
        out[key] = m.group(1) if m else '?'
    return out


# ------------------------------------------------------------------ bench
def cmd_bench(a):
    print(f'OpenSSL: {subprocess.check_output([OPENSSL, "version"]).decode().strip()}')
    base = []
    for _ in range(10):
        t = time.perf_counter()
        subprocess.run([OPENSSL, 'version'], stdout=subprocess.DEVNULL)
        base.append((time.perf_counter() - t) * 1000)
    print(f'process start-up baseline: median {statistics.median(base):.1f} ms '
          f'(included in every time below)\n')

    rows = []
    proxy = CountingProxy(); proxy.start()          # one proxy for the whole run
    for name, groups, chain in SCENARIOS:
        try:
            srv = start_server(chain, groups)
        except RuntimeError as e:
            print(f'{name}: SKIPPED ({e})')
            continue
        proxy.stats.clear()
        times, info = [], {}
        for i in range(a.runs):
            t = time.perf_counter()
            r = subprocess.run(client_cmd(PROXY_PORT, groups, chain), stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=30)
            times.append((time.perf_counter() - t) * 1000)
            if i == 0:
                info = parse_brief((r.stdout + r.stderr).decode(errors='replace'))
        time.sleep(0.3)
        srv.kill(); srv.wait()
        if not proxy.stats:
            print(f'{name}: no connections recorded'); continue
        c2s = statistics.median(s[0] for s in proxy.stats)
        s2c = statistics.median(s[1] for s in proxy.stats)
        rows.append((name, int(c2s), int(s2c), int(c2s + s2c), statistics.median(times),
                     pct(times, 95), info))
        time.sleep(0.3)
    proxy.stop = True

    print(f'{"scenario":38s} {"C->S B":>7s} {"S->C B":>7s} {"total B":>8s} {"median ms":>9s} '
          f'{"p95 ms":>7s}  group / signature / verify')
    for n, c, s, t, med, p95, info in rows:
        print(f'{n:38s} {c:7d} {s:7d} {t:8d} {med:9.1f} {p95:7.1f}  '
              f'{info["group"]} / {info["sig"]} / {info["verify"]}')
    if rows:
        b = rows[0][3]
        print('\nHandshake size relative to classical (A):')
        for n, c, s, t, *_ in rows:
            print(f'  {n:38s} {t / b:5.1f}x  ({t - b:+d} bytes)')
    with open('tls_results.csv', 'w') as f:
        f.write('scenario,c2s_bytes,s2c_bytes,total_bytes,median_ms,p95_ms,group,sig,verify\n')
        for n, c, s, t, med, p95, info in rows:
            f.write(f'"{n}",{c},{s},{t},{med:.1f},{p95:.1f},{info["group"]},{info["sig"]},{info["verify"]}\n')
    print('\nSaved tls_results.csv')


# ------------------------------------------------------------------ message breakdown
MSG_RE = re.compile(r'(>>>|<<<)\s+TLS 1\.3,\s*(?:Handshake|Handshake\s*)\s*\[length\s+([0-9a-fA-F]+)\],\s*(\w+)')
MSG_RE2 = re.compile(r'(>>>|<<<)\s+TLS 1\.[23],\s*(\w+)\s*\[length\s+([0-9a-fA-F]+)\]')


def cmd_msgs(a):
    print('Per-message handshake sizes (bytes of handshake payload, from s_client -msg)\n')
    table = {}
    for name, groups, chain in SCENARIOS:
        try:
            srv = start_server(chain, groups)
        except RuntimeError as e:
            print(f'{name}: SKIPPED ({e})'); continue
        r = subprocess.run(client_cmd(SERVER_PORT, groups, chain, msg=True),
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        srv.kill(); srv.wait()
        text = (r.stdout + r.stderr).decode(errors='replace')
        sizes = {}
        for m in MSG_RE.finditer(text):
            sizes.setdefault(m.group(3), int(m.group(2), 16))
        table[name] = sizes
    keys = ['ClientHello', 'ServerHello', 'EncryptedExtensions', 'Certificate',
            'CertificateVerify', 'Finished']
    short = {'ClientHello': 'ClientHello', 'ServerHello': 'ServerHello', 'EncryptedExtensions': 'EncExt',
             'Certificate': 'Certificate', 'CertificateVerify': 'CertVerify', 'Finished': 'Finished'}
    print(f'{"scenario":38s} ' + ' '.join(f'{short[k]:>11s}' for k in keys))
    for n, sz in table.items():
        print(f'{n:38s} ' + ' '.join(f'{sz.get(k, 0):11d}' for k in keys))
    print('\nRead it like this: ClientHello grows with the KEM public key (ML-KEM-768 = 1184 B),')
    print('ServerHello grows with the KEM ciphertext (1088 B), and Certificate + CertificateVerify')
    print('grow with the signature algorithm. Hybrid key exchange adds ~2.3 KB; ML-DSA authentication')
    print('adds ~15 KB (certificates ~11.5 KB + CertificateVerify ~3.2 KB). That is why\nauthentication is the harder half of PQ-TLS.')


# ------------------------------------------------------------------ dual-certificate agility
def cmd_dual(a):
    """One server, two certificates (ECDSA + ML-DSA). Each client gets what it can verify."""
    c, p = f'{PKI}/classical', f'{PKI}/pq'
    both = 'both_roots.pem'
    with open(both, 'wb') as f:
        f.write(open(f'{c}/root.crt', 'rb').read() + open(f'{p}/root.crt', 'rb').read())
    srv = start_server('classical', 'X25519MLKEM768',
                       extra=['-dcert', f'{p}/leaf.crt', '-dkey', f'{p}/leaf.key',
                              '-dcert_chain', f'{p}/int.crt'])
    print('Server holds BOTH an ECDSA chain and an ML-DSA chain. The client picks via signature_algorithms.\n')
    for label, sigalgs in (('legacy client (ECDSA only)', 'ecdsa_secp256r1_sha256'),
                           ('PQ-aware client (ML-DSA-65)', 'mldsa65'),
                           ('both offered, PQ preferred', 'mldsa65:ecdsa_secp256r1_sha256')):
        cmd = [OPENSSL, 's_client', '-connect', f'{HOST}:{SERVER_PORT}', '-tls1_3',
               '-groups', 'X25519MLKEM768', '-CAfile', both, '-verify_hostname', 'localhost',
               '-verify_return_error', '-servername', 'localhost', '-brief', '-sigalgs', sigalgs]
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        t = (r.stdout + r.stderr).decode(errors='replace')
        info = parse_brief(t)
        issuer = re.search(r'Issuer.*?CN\s*=\s*([^\n,]+)|issuer.*?CN\s*=\s*([^\n,]+)', t)
        print(f'{label:32s} -> signature type: {info["sig"]:12s} verify: {info["verify"]}')
    srv.kill(); srv.wait()
    print('\nThis is the migration pattern: ship both chains, let capabilities decide, '
          'retire ECDSA when the fleet is ready.')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('bench'); p.add_argument('--runs', type=int, default=30); p.set_defaults(fn=cmd_bench)
    p = sub.add_parser('msgs'); p.set_defaults(fn=cmd_msgs)
    p = sub.add_parser('dual'); p.set_defaults(fn=cmd_dual)
    a = ap.parse_args()
    a.fn(a)
