#!/usr/bin/env python3
"""
mutation_lab.py - break mlkem.py on purpose and watch NIST's test vectors catch you.

This is called MUTATION TESTING: change one small thing in correct code, and check that your
tests notice. If a test suite cannot catch a planted bug, it cannot be trusted to catch a real one.

Run it from the folder that holds mlkem.py, grader_full.py and gen-val/ :
    python3 mutation_lab.py gen-val/json-files

It edits mlkem.py temporarily and ALWAYS puts the original back (even if you press Ctrl+C).
A backup copy is saved as mlkem.py.orig first, just in case.
"""
import shutil
import subprocess
import sys

VECTORS = sys.argv[1] if len(sys.argv) > 1 else 'gen-val/json-files'

EXPERIMENTS = [
    ('E1  swap the matrix index order (j,i -> i,j)',
     "bytes([j, i])", "bytes([i, j])",
     'The standard says A[i][j] uses rho || j || i. Swapping makes a different (transposed) matrix.'),
    ('E2  decompress: round -> floor',
     "return (y * Q + (1 << (d - 1))) >> d", "return (y * Q) >> d",
     'A tiny rounding slip. Notice that SOME tests still pass.'),
    ('E3  ML-KEM-512 only: noise width eta1 3 -> 2',
     "'ML-KEM-512':  (2, 3, 2, 10, 4)", "'ML-KEM-512':  (2, 2, 2, 10, 4)",
     'Wrong parameter for one security level. Only that level should fail.'),
    ('E4  inverse NTT: forget to divide by 128',
     "return [(x * 3303) % Q for x in f]", "return [x % Q for x in f]",
     'KeyGen uses only the forward NTT, so key generation still passes.'),
    ('E5  encapsulation key check: skip the modulus check',
     "        if byte_encode(byte_decode(blk, 12), 12) != blk:   # modulus check\n            return False\n", "",
     'Valid keys still pass. Only the INVALID keys (coefficient >= q) slip through.'),
    ('E6  decapsulation: skip the re-encryption check',
     "return K2 if c == c2 else K_bar", "return K2",
     'Honest ciphertexts still pass. Tampered ones now return the real key.'),
]

shutil.copy('mlkem.py', 'mlkem.py.orig')
original = open('mlkem.py').read()

try:
    for name, old, new, lesson in EXPERIMENTS:
        print(f'\n{name}\n   lesson: {lesson}')
        if old not in original:
            print('   (pattern not found - your mlkem.py differs from mine; skipping)')
            continue
        open('mlkem.py', 'w').write(original.replace(old, new, 1))
        r = subprocess.run([sys.executable, 'grader_full.py', VECTORS], capture_output=True, text=True)
        lines = r.stdout.splitlines()
        total = [l for l in lines if l.startswith('TOTAL')]
        print('   ' + (total[0] if total else 'grader crashed: ' + (r.stderr.strip().splitlines() or ['?'])[-1]))
        mode = ''
        for l in lines:
            if l.startswith('== keyGen'):
                mode = 'keyGen'
            elif l.startswith('== encaps'):
                mode = 'encap/decap'
            if 'FAIL' in l and 'group' in l:
                print(f'     [{mode}] {l.strip()[:80]}')
finally:
    open('mlkem.py', 'w').write(original)
    print('\nOriginal mlkem.py restored. (Backup also saved as mlkem.py.orig)')
