#!/usr/bin/env python3
"""
Lab 12 (Azure series, Post 1) - Which of MY Azure endpoints really negotiate post-quantum TLS?

It connects to each host with OpenSSL (>= 3.5), offers  X25519MLKEM768  first and common classical groups
(X25519, P-256, P-384) as fallbacks, and records which key-exchange group the SERVER actually chose.

  PQ         -> the server picked a hybrid ML-KEM group (harvest-now-decrypt-later protected)
  CLASSICAL  -> the server fell back to X25519 / P-256 / P-384 (quantum-vulnerable key exchange)
  FAILED     -> no TLS 1.3 handshake (timeout, DNS, TLS 1.2 only, firewall...)

SELF-CHECK: it first probes a control host that is known to support hybrid ML-KEM. If the control
does not come back PQ, YOUR local OpenSSL is the problem and the Azure results would be meaningless,
so the script stops. (This prevents the classic mistake of blaming the cloud for a client problem.)

Usage:
    OPENSSL=/path/to/openssl python3 12_azure_pqtls_probe.py host1 host2 ...
    python3 12_azure_pqtls_probe.py --file hosts.txt
    python3 12_azure_pqtls_probe.py --file hosts.txt --control www.cloudflare.com

hosts.txt: one hostname per line, '#' starts a comment. Put YOUR OWN endpoints in it:
    myvault.vault.azure.net
    mystorage.blob.core.windows.net
    myapp.azurewebsites.net
    myfrontdoor-xxxx.z01.azurefd.net
    mygateway-public-dns-name.westeurope.cloudapp.azure.com

Results depend on region, SKU, TLS policy and the edge you hit. Re-run on another day and from
another network before you publish a conclusion.
"""
import argparse
import csv
import datetime
import os
import re
import subprocess
import sys

OPENSSL = os.environ.get('OPENSSL', 'openssl')
# PQ hybrid preferred; then every common classical group, so a server that dislikes X25519
# (some Microsoft front ends reset the connection) can still answer with P-256 / P-384.
OFFER = 'X25519MLKEM768:X25519:secp256r1:secp384r1'


def probe(host, port=443, timeout=20, offer=OFFER):
    cmd = [OPENSSL, 's_client', '-connect', f'{host}:{port}', '-servername', host,
           '-tls1_3', '-groups', offer, '-brief']
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return dict(host=host, verdict='FAILED', group='-', detail='timeout')
    text = (r.stdout + r.stderr).decode(errors='replace')
    g = re.search(r'(?:Negotiated TLS1\.3 group|Peer Temp Key):\s*([^\s,]+)', text)
    proto = re.search(r'Protocol version:\s*(\S+)', text)
    if g and proto and proto.group(1) == 'TLSv1.3':
        group = g.group(1)
        verdict = 'PQ' if 'MLKEM' in group.upper() or 'KYBER' in group.upper() else 'CLASSICAL'
        return dict(host=host, verdict=verdict, group=group, detail=proto.group(1))
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    err = next((l for l in lines if any(k in l.lower() for k in ('error', 'fail', 'alert', 'refused', 'unknown', 'reset', 'unreachable'))),
               ' | '.join(lines[-2:]) if lines else 'no output at all')
    return dict(host=host, verdict='FAILED', group='-', detail=err[:90])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('hosts', nargs='*')
    ap.add_argument('--file')
    ap.add_argument('--offer', default=OFFER, help='groups to offer, e.g. X25519 to test without ML-KEM')
    ap.add_argument('--control', default='www.cloudflare.com',
                    help='a host you expect to support hybrid ML-KEM (checks YOUR client)')
    a = ap.parse_args()

    hosts = list(a.hosts)
    if a.file:
        for line in open(a.file):
            line = line.split('#')[0].strip()
            if line:
                hosts.append(line)
    if not hosts:
        sys.exit('give hostnames or --file hosts.txt')

    ver = subprocess.run([OPENSSL, 'version'], capture_output=True).stdout.decode().strip()
    print(f'client: {ver}\nclient offers: {a.offer}\n')

    c = probe(a.control)
    if c['verdict'] != 'PQ':
        sys.exit(f'SELF-CHECK FAILED: control host {a.control} gave {c["verdict"]} ({c["group"]}, {c["detail"]}).\n'
                 'Your OpenSSL probably lacks ML-KEM (need >= 3.5) or the control host changed. '
                 'Fix that first; Azure results would be meaningless.')
    print(f'self-check OK: control {a.control} negotiated {c["group"]}\n')

    rows = [probe(h, offer=a.offer) for h in hosts]
    print(f'{"host":58s} {"verdict":10s} {"group":16s} detail')
    for r in rows:
        print(f'{r["host"][:58]:58s} {r["verdict"]:10s} {r["group"]:16s} {r["detail"]}')

    stamp = datetime.date.today().isoformat()
    out = f'azure_pqtls_{stamp}.csv'
    with open(out, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['date', 'host', 'verdict', 'group', 'detail'])
        w.writeheader()
        for r in rows:
            w.writerow(dict(date=stamp, **r))
    n_pq = sum(r['verdict'] == 'PQ' for r in rows)
    print(f'\n{n_pq} of {len(rows)} endpoints negotiated a post-quantum hybrid group. Saved {out}')
    print('Reminder: this tests the key exchange on ONE path at ONE time. It says nothing about '
          'certificates/signatures (still classical on almost every public endpoint).')


if __name__ == '__main__':
    main()
