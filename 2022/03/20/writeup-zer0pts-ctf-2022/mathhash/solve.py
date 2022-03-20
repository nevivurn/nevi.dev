#!/usr/bin/env python3

from pwn import *

charset = bytes(range(0x20, 0x7f))

r = remote('misc.ctf.zer0pts.com', 10001)
#r = process(['python', './server.py'])

def query(q):
    q = bytes([-c & 0xff for c in q])

    r.recvuntil(b'Key: ')
    r.sendline(enhex(q).encode())

    data = r.recvline_startswith(b'Hash: ').split()[1][2:]
    data = data.rjust(16, b'0')
    base = unhex(data)[0] & 0b1100000

    return base

known = b'zer0pts'
last = query(known)

while known[-1] != ord('}'):
    for guess in charset:
        cur = query(known + bytes([guess]))

        if cur ^ last in [0b1000000, 0b100000]:
            known += bytes([guess])
            last = cur
            info(known.decode())
            break
success(known.decode())
