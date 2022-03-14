#!/usr/bin/env python3

from pwn import *

def trailing(x):
    a = 0
    for _ in range(15):
        if x & 1:
            break
        x >>= 1
        a += 1
    return a

def comp_hash(s, k1, k2):
    out = ''
    for x in s:
        for y in s:
            out += hex(trailing((k1 ^ x) * (k2 ^ y)))[2:]
    return out

# Precompute first stage
first = bytes(range(16))
precompute = {}

with log.progress('Precomputing...') as p:
    for x in range(256):
        for y in range(256):
            comp = comp_hash(first, x, y)
            s = precompute.get(comp, set())
            s.add(x)
            s.add(y)
            precompute[comp] = s

#r = process('./main.py')
r = remote('misc1.utctf.live', 5000)

with log.progress('Solving...') as p:
    for i in range(100):
        p.status(f'{i}/100')

        r.sendafter(b';)\n', first)
        line = r.recvline().decode().rstrip()

        poss = precompute[line]
        second = bytes(poss).rjust(16, b'\x00')

        r.sendafter(b'...\n', second)
        line = r.recvline().decode().rstrip()

        for x in poss:
            for y in poss:
                if comp_hash(second, x, y) == line:
                    r.sendlineafter(b'k1:\n', f'{x}'.encode())
                    r.sendlineafter(b'k2:\n', f'{y}'.encode())

success(r.recvall().decode())
