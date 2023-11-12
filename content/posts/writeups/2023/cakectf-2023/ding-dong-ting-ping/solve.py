#!/usr/bin/env python3

from pwn import *

#p = process(['python3', 'server.py'])
p = remote('crypto.2023.cakectf.com', 11111)

want = b'|user=root|date'

def query(query):
    p.sendlineafter(b': ', b'1')
    p.sendlineafter(b': ', b64e(query).encode())
    p.recvuntil(b'=> ')
    return b64d(p.recvline())

cipher = query(b'room|date')

IV = cipher[:16]
prefix_enc = cipher[16:32]
first_enc = cipher[32:48]

prefix_hash = md5sum(prefix_enc)
first_hash = md5sum(first_enc)

with log.progress('guess') as prog:
    for guess in range(0, 256):
        prog.status(f'{guess}')

        cur_want = bytes([guess]) + want
        block = xor(cur_want, first_hash, prefix_hash)

        resp = query(b'room|date' + block)
        resp = resp[48:]

        p.sendlineafter(b': ', b'2')
        p.sendlineafter(b'cookie: ', b64e(IV + prefix_enc + resp).encode())

        line = p.recvline().decode()
        if 'root' in line:
            prog.success()
            p.interactive()
            break
