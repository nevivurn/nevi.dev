#!/usr/bin/env python3

from pwn import *
from Crypto.Util.number import inverse

T = remote('crypto.2023.cakectf.com', 10444)

T.recvuntil(b'p = ')
p = int(T.recvline().strip().decode())

T.recvuntil(b'g = ')
g = int(T.recvline().strip().decode())

T.recvuntil(b'vkey = ')
vkey = safeeval.const(T.recvline().strip().decode())
w, v = vkey

magic_word = b'cake_does_not_eat_cat'
m = int(enhex(sha512sum(magic_word)), 16)

y = inverse(w, p-1) * v % (p-1)

a = (inverse(w, p-1) * m + 1) % (p-1)
b = inverse(y, p-1)

s = pow(g, a, p)
t = pow(g, b, p)

T.sendlineafter(b': ', b'V')
T.sendlineafter(b'message: ', magic_word)
T.sendlineafter(b's: ', str(s).encode())
T.sendlineafter(b't: ', str(t).encode())
T.interactive()
