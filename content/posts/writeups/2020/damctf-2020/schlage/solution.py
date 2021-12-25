#!/usr/bin/env python3

from pwn import *
import time

c = remote('chals.damctf.xyz', 31932)

c.sendlineafter('>', '3')
c.sendlineafter('>', '3449466328')
c.sendlineafter('>', '1')
c.sendlineafter('>', '99')
c.sendlineafter('>', '5')
c.sendlineafter('>', '1413036362')
c.sendlineafter('>', '2')

c.recvline_contains('I wonder what it means?')
seed = int(c.recvline())

cc = process(['./rand', str(seed)])
a = int(cc.recvline())
b = int(cc.recvline())
cc.close()

c.sendlineafter("What's your favorite number?", str(a))
c.sendlineafter('>', '4')
c.sendlineafter('>', chr((0x123//3) ^ b) * 3)
log.success(c.recvall().split(b'\n')[-3])
