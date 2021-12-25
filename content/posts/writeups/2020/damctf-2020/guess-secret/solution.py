#!/usr/bin/env python3

from pwn import *

import string

charset = '0123456789abcdef'

c = remote('chals.damctf.xyz', 30308)

known = ''
while len(known) < 32:
    prev = None
    prev_chr = None
    for x in charset:
        c.sendlineafter('please give me your string...', 'dam{'+known+x)
        c.readline()
        data = safeeval.const(c.readline())

        if not prev:
            prev = len(data)
            prev_chr = x
        else:
            if prev < len(data):
                known += prev_chr
                log.info('known: %s', known)
                break
            if prev > len(data):
                known += x
                log.info('known: %s', known)
                break
    else:
        log.error('known')

log.success('damctf{%s}', known)
