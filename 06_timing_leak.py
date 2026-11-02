#!/usr/bin/env python3
"""
Lab 6 - Finding timing side channels with a statistical test (the dudect idea)

THEORY
  A function is "constant-time" if its running time does not depend on secret data.
  dudect (Reparaz, Balasch, Verbauwhede) tests this statistically:
    1. Make two classes of inputs (e.g. 'fixed' vs 'random', or 'matches early' vs 'late').
    2. Time the function many times, interleaving the classes randomly.
    3. Crop extreme outliers (interrupts, GC) and run Welch's t-test on the two classes.
    4. |t| > ~4.5 means the two classes take measurably different time => LEAK.
  A pass does NOT prove constant-time (absence of evidence), but a fail proves a leak.

WHAT THIS LAB RUNS
  A) leaky_equal()      early-exit byte compare       -> should FAIL (big |t|)
  B) hmac.compare_digest constant-time compare        -> should PASS (small |t|)
  C) mlkem.decaps_internal, valid vs corrupted ciphertext (implicit rejection path)
     NOTE: pure Python cannot prove constant-time; this just shows the METHOD.
  For real libraries use dudect itself (https://github.com/oreparaz/dudect) or
  valgrind-based tools on liboqs.

    python3 06_timing_leak.py              # ~1-2 minutes
    python3 06_timing_leak.py --n 60000    # more samples = more power
"""
import argparse
import hmac
import math
import os
import random
import statistics
import time

THRESH = 4.5


def welch_t(a, b):
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    va, vb = statistics.pvariance(a, ma), statistics.pvariance(b, mb)
    return (ma - mb) / math.sqrt(va / len(a) + vb / len(b) + 1e-30)


def crop(samples, pct):
    cut = sorted(samples)[int(len(samples) * pct) - 1]
    return [s for s in samples if s <= cut]


def measure(fn, make_input, n):
    """Interleave classes 0/1 randomly; return per-class timing lists (ns)."""
    t = ([], [])
    inputs = [(random.getrandbits(1)) for _ in range(n)]
    prepared = [make_input(c) for c in inputs]
    for x in prepared[:min(500, n)]:          # warm-up: let caches and CPU speed settle (not recorded)
        fn(*x)
    for c, x in zip(inputs, prepared):
        t0 = time.perf_counter_ns()
        fn(*x)
        t[c].append(time.perf_counter_ns() - t0)
    return t


def worst_t(t):
    # dudect crops at several percentiles and keeps the largest |t|
    return max(abs(welch_t(crop(t[0], p), crop(t[1], p))) for p in (1.0, 0.99, 0.95, 0.90))


def evaluate(name, fn, make_input, n, expect_leak=None):
    """Run the experiment TWICE. Declare a leak only if BOTH runs exceed the threshold.
    One run above the line is 'inconclusive': it is how a noisy machine fools you."""
    runs = []
    for _ in range(2):
        t = measure(fn, make_input, n)
        runs.append((worst_t(t), statistics.fmean(t[0]), statistics.fmean(t[1])))
    over = [r[0] > THRESH for r in runs]
    if all(over):
        verdict = 'LEAK DETECTED (both runs)'
    elif any(over):
        verdict = 'inconclusive (only one run above the line: probably noise, rerun with a bigger --n)'
    else:
        verdict = 'no leak detected'
    tag = ''
    if expect_leak is not None:
        tag = '  (as expected)' if (all(over) == expect_leak and not (any(over) and not all(over))) else '  (not as expected: see note)'
    print(f'{name:44s} run1 |t| = {runs[0][0]:8.1f}   run2 |t| = {runs[1][0]:8.1f}   -> {verdict}{tag}')
    d = runs[1][1] - runs[1][2]
    print(f'{"":44s} mean time class0 = {runs[1][1]:9.0f} ns   class1 = {runs[1][2]:9.0f} ns   (difference {d:+.0f} ns)')
    return runs


# ---------------------------------------------------------------- A: leaky compare
def leaky_equal(a, b):
    """The classic bug: returns at the FIRST differing byte."""
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
    return True


SECRET = os.urandom(32)


def make_cmp_input(c):
    guess = bytearray(SECRET)
    # class 0: wrong at the FIRST byte;  class 1: wrong only at the LAST byte
    guess[0 if c == 0 else 31] ^= 0xFF
    return (SECRET, bytes(guess))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=40000)
    ap.add_argument('--skip-mlkem', action='store_true')
    a = ap.parse_args()
    random.seed(1)

    print(f'samples per test: {a.n}  |  leak threshold |t| > {THRESH}\n')
    print('A/B  comparing a secret MAC/tag: attacker learns how many leading bytes were right')
    evaluate('A  leaky_equal (early exit)', leaky_equal, make_cmp_input, a.n, expect_leak=True)
    evaluate('B  hmac.compare_digest (constant-time)', hmac.compare_digest, make_cmp_input, a.n, expect_leak=False)

    print('\nWhat A means in practice: with a remote timing oracle an attacker recovers a secret tag '
          'one byte at a time (~256 guesses per byte instead of 2^256).\n')

    if not a.skip_mlkem:
        try:
            import mlkem
        except ImportError:
            print('(skip C: put mlkem.py in this folder)')
            return
        ps = 'ML-KEM-512'
        ek, dk = mlkem.keygen_internal(os.urandom(32), os.urandom(32), ps)
        _, ct = mlkem.encaps_internal(ek, os.urandom(32), ps)

        def make_ct(c):
            if c == 0:
                return (dk, ct)                            # valid ciphertext
            bad = bytearray(ct)
            bad[random.randrange(len(bad))] ^= 1           # invalid -> implicit rejection
            return (dk, bytes(bad))

        n = max(500, a.n // 40)
        print(f'C  ML-KEM decapsulation: valid vs corrupted ciphertext ({n} samples, pure Python)')
        evaluate('C  mlkem.decaps_internal (valid vs invalid)',
                 lambda d, c: mlkem.decaps_internal(d, c, ps), make_ct, n)
        print('   Decaps ALWAYS re-encrypts, then picks the real key or the rejection key. A correct\n'
              '   implementation therefore takes the same time either way. A leak here would reveal\n'
              '   whether a chosen ciphertext was valid (the classic KyberSlash/FO-oracle risk).\n'
              '   Python gives no guarantee: interpreter noise and big-int arithmetic dominate.')


if __name__ == '__main__':
    main()
