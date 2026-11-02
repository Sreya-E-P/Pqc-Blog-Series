#!/usr/bin/env python3
"""
Experiment 10 - Why does ML-KEM decryption work? Measure the noise.

THEORY
  Decryption computes   w = v - s^T * u   which equals   (message * 1665) + noise   (mod 3329).
  Each message bit is encoded as 0 or 1665 (about q/2). To read a bit back we round w to
  whichever of 0 or 1665 is closer. That works as long as |noise| < q/4 = 832.
  So the whole scheme is a bet that the noise stays far below 832. This script measures it.

  It also shows what happens if the noise were bigger (we cheat by adding extra noise):
  decryption starts to fail. That is a decryption failure, and real ML-KEM is designed
  so its failure probability is astronomically small (about 2^-139 or less).

Run (needs mlkem.py in the same folder):
    python3 10_noise_demo.py            # 200 trials per parameter set
    python3 10_noise_demo.py --trials 500
"""
import argparse
import os
import random

import mlkem
from mlkem import Q, N, PARAMS

HALF = (Q + 1) // 2          # 1665 : what a '1' bit is encoded as
BUDGET = Q // 4              # 832  : maximum noise we can tolerate


def centered(x):
    """Map 0..q-1 to the range -1664..1664 (distance from zero)."""
    x %= Q
    return x - Q if x > Q // 2 else x


def noise_of_one_decryption(ps):
    """Run one K-PKE encrypt/decrypt and return the largest |noise| across the 256 coefficients."""
    k, eta1, eta2, du, dv = PARAMS[ps]
    ek, dk = mlkem.kpke_keygen(os.urandom(32), ps)
    m = os.urandom(32)
    c = mlkem.kpke_encrypt(ek, m, os.urandom(32), ps)

    # --- repeat decryption but keep w (before rounding) ---
    c1, c2 = c[:32 * du * k], c[32 * du * k:]
    u = [[mlkem.decompress(x, du) for x in mlkem.byte_decode(c1[32 * du * i:32 * du * (i + 1)], du)]
         for i in range(k)]
    v = [mlkem.decompress(x, dv) for x in mlkem.byte_decode(c2, dv)]
    s_hat = [mlkem.byte_decode(dk[384 * i:384 * (i + 1)], 12) for i in range(k)]
    acc = [0] * N
    for j in range(k):
        acc = mlkem.vadd(acc, mlkem.ntt_mul(s_hat[j], mlkem.ntt(u[j])))
    w = mlkem.vsub(v, mlkem.ntt_inv(acc))

    bits = mlkem.byte_decode(m, 1)
    noise = [centered(w[i] - bits[i] * HALF) for i in range(N)]
    ok = mlkem.kpke_decrypt(dk, c, ps) == m
    return max(abs(x) for x in noise), ok, w, bits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--trials', type=int, default=200)
    a = ap.parse_args()

    print(f'q = {Q}.  A bit is stored as 0 or {HALF}.  Rounding works while |noise| < q/4 = {BUDGET}.\n')
    print(f'{"parameter set":13s} {"trials":>6s} {"largest noise seen":>19s} {"% of budget used":>17s}  decrypt ok')
    for ps in PARAMS:
        worst, all_ok = 0, True
        for _ in range(a.trials):
            n, ok, _, _ = noise_of_one_decryption(ps)
            worst = max(worst, n)
            all_ok &= ok
        print(f'{ps:13s} {a.trials:6d} {worst:19d} {100 * worst / BUDGET:16.1f}%  {all_ok}')

    print('\nNow cheat: add extra random noise to w before rounding and watch decryption break.')
    _, _, w, bits = noise_of_one_decryption('ML-KEM-768')
    random.seed(7)
    print(f'{"extra noise up to":>18s}  {"bits decoded wrongly (of 256)":>30s}')
    for extra in (0, 200, 400, 600, 800, 1000, 1400):
        wrong = 0
        for i in range(N):
            noisy = (w[i] + random.randint(-extra, extra)) % Q
            decoded = mlkem.compress(noisy, 1)
            wrong += (decoded != bits[i])
        print(f'{extra:18d}  {wrong:30d}')
    print('\nReal noise sits far below the budget, so the wrong-bit count is 0 in normal use.')
    print('If an attacker (or a bug) pushed noise past ~832, bits would flip and decryption would fail.')


if __name__ == '__main__':
    main()
