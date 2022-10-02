#!/usr/bin/env python3

from pwn import *
from itertools import permutations

with open('flag.enc', 'rb') as f:
    data = f.read()

now = xor(data[-18:], 0x42)
enc = data[:-18]

random.seed(now)
key = [random.randrange(256) for _ in enc]
enc = xor(enc, key)

info('dec: %s' % enc.decode())

def decrypt(message, key):
    size = len(message)
    out = [0] * size
    for i in key:
        for j in range(i, size, len(key)):
            out[j] = message[0]
            message = message[1:]
    return bytes(out)

known = b'SEKAI{'

with log.progress('brute') as prog:
    for p in permutations(range(8)):
        prog.status(str(p))

        dec = enc
        for _ in range(42):
            dec = decrypt(dec, p)
        if dec.startswith(b'SEKAI{'):
            prog.success(str(p))
            success(dec.decode())
            break
