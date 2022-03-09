#!/usr/bin/env python3

from pwn import *

c = remote('chals.damctf.xyz', 30327)

prev, data = None, None
for pad in range(1, 18):
    c.sendlineafter('?', '1')
    c.sendlineafter('?', str(pad))
    c.sendafter('!', '0' * pad)
    cur = int(c.recvline_contains('length').split()[-1])

    log.info('pad = %d; length = %d', pad, cur)
    if prev and prev != cur:
        data = c.recvline()
        break
    prev = cur

data = safeeval.const(data)
data = b'p\xe8(\xfd\xec\x86dc\xa0n\x94\xf1b,\xb6\xd9qLZ\x84\xb8\xe4\xc4\x0f\xb8\x7f\xb3\x1b\xf5\xcb\x80\xe4i\x1a\\JS\xc9\xa4c\xc6\x01\x90 `\xc1\xd3~f?%\xee.\xf0\x1e9\x94\x17\x1a\xfe\xcc\xe2\xf5\xad\xcd?y\x0b\xc4\xb5\xea\xf0\xe3\x83\xe2\x8f{\xc5\xcct\xe7\x87\x06\xf3\x8f\xc9\xf1\x82\x08Kt\x06\xe7\xe4\xbe\xce;\xf2(\x1b\x9a\xce\x81\x80\x82\n:\xb9\xa9>\xfdF'
flag_len = len(data) - 16 - 64 - pad - 16
log.info('data: %s', data)
log.info('flag_len: %d', flag_len)

blocks = group(16, data)
blocks = blocks[4:6]

known_len = 0
known_len = 3
known_block = bytearray(16)
known_block = bytearray(unhex('000000000000000000000000780e3434'))

while known_len < 16:
    c.sendlineafter('?', '2')
    c.sendlineafter('?', '32')
    c.sendafter('!', xor(blocks[-2], bytes(known_block)) + blocks[-1])

    c.recvline()
    line = c.recvline()
    if b'ERROR' in line:
        known_block[-(known_len+1)] += 1
        continue

    log.info('known: %d/16; current: %s', known_len, known_block.hex())

    known_len += 1
    for i in range(known_len):
        known_block[-(i+1)] ^= (known_len) ^ (known_len+1)

flag = xor(bytes(known_block), chr(known_len+1))[:flag_len]
log.success(flag)
