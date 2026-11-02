"""
grader_full.py - grade mlkem.py against NIST's ACVP ML-KEM sample vectors.

Usage:
    python3 grader_full.py /path/to/ACVP-Server/gen-val/json-files
"""
import json
import sys
import time

import mlkem

root = sys.argv[1] if len(sys.argv) > 1 else 'gen-val/json-files'


def load(folder, name):
    return json.load(open(f'{root}/{folder}/{name}'))


def index_expected(E):
    return {(g['tgId'], t['tcId']): t for g in E['testGroups'] for t in g['tests']}


def hexb(s):
    return bytes.fromhex(s)


def same(a_bytes, b_hex):
    return a_bytes.hex().upper() == b_hex.upper()


total_ok = total_bad = 0


def report(tg, func, ps, ok, bad, secs):
    global total_ok, total_bad
    total_ok += ok
    total_bad += bad
    status = 'PASS' if bad == 0 and ok > 0 else 'FAIL'
    print(f'group {tg:2d} {func:24s} {ps:12s} ok={ok:3d} bad={bad} {secs:5.1f}s  {status}')


# ------------------------------------------------------------- keyGen
P = load('ML-KEM-keyGen-FIPS203', 'prompt.json')
E = index_expected(load('ML-KEM-keyGen-FIPS203', 'expectedResults.json'))
print('== keyGen ==')
for g in P['testGroups']:
    ok = bad = 0
    t0 = time.time()
    for t in g['tests']:
        ek, dk = mlkem.keygen_internal(hexb(t['d']), hexb(t['z']), g['parameterSet'])
        want = E[(g['tgId'], t['tcId'])]
        if same(ek, want['ek']) and same(dk, want['dk']):
            ok += 1
        else:
            bad += 1
            print('  mismatch tcId', t['tcId'])
    report(g['tgId'], 'keyGen', g['parameterSet'], ok, bad, time.time() - t0)

# ------------------------------------------------------------- encap/decap
P = load('ML-KEM-encapDecap-FIPS203', 'prompt.json')
E = index_expected(load('ML-KEM-encapDecap-FIPS203', 'expectedResults.json'))
print('== encapsulation / decapsulation / key checks ==')
for g in P['testGroups']:
    f, ps = g['function'], g['parameterSet']
    ok = bad = 0
    t0 = time.time()
    for t in g['tests']:
        want = E[(g['tgId'], t['tcId'])]
        if f == 'encapsulation':
            K, c = mlkem.encaps_internal(hexb(t['ek']), hexb(t['m']), ps)
            good = same(K, want['k']) and same(c, want['c'])
        elif f == 'decapsulation':
            K = mlkem.decaps_internal(hexb(t['dk']), hexb(t['c']), ps)
            good = same(K, want['k'])
        elif f == 'encapsulationKeyCheck':
            good = mlkem.ek_check(hexb(t['ek']), ps) == want['testPassed']
        elif f == 'decapsulationKeyCheck':
            good = mlkem.dk_check(hexb(t['dk']), ps) == want['testPassed']
        else:
            continue
        ok += good
        bad += (not good)
        if not good:
            print('  mismatch tcId', t['tcId'])
    report(g['tgId'], f, ps, ok, bad, time.time() - t0)

print(f'\nTOTAL: {total_ok} passed, {total_bad} failed')
sys.exit(1 if total_bad else 0)
