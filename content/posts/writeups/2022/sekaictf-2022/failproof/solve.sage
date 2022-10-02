#!/usr/bin/env sage

from pwn import *
from hashlib import sha256

def gen_pubkey(secret: bytes) -> list:
    def hash(m): return sha256(m).digest()
    state = hash(secret)
    pubkey = []
    for _ in range(len(hash(b'0')) * 4):
        pubkey.append(int.from_bytes(state, 'big'))
        state = hash(state)
    return pubkey

pubkey = []
enc = []

for _ in range(2):
    with remote('challs.ctf.sekai.team', 3001) as p:
    #with process(['python', 'source.py']) as p:
        secret = unhex(p.recvline().strip())
        pubkey += gen_pubkey(secret)

        v = safeeval.expr(p.recvline().strip())

        if len(enc) == 0:
            enc = v
        else:
            enc = [a+b for (a, b) in zip(enc, v)]

M = Matrix(ZZ, len(pubkey), 256)
for (i, key) in enumerate(pubkey):
    b = bits(key)
    M[i] = [0] * (256-len(b)) + b

ans = b''
for chunk in enc:
    x = M \ vector(ZZ, chunk)
    ans += unbits(x).rstrip(b'\x00')

success(ans.decode())
