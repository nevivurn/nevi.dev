#!/usr/bin/env python3

from pwn import *

while True:
    #with process(['go', 'run', 'robust_cbc.go']) as p:
    with remote('challs.ctf.sekai.team', 7000) as p:
        plain = b'Sekai'

        p.sendlineafter(b'Enter your choice: ', b'2')
        p.sendlineafter(b'Enter message in hex: ', enhex(plain).encode())
        mac_lsb = unhex(p.recvline_startswith(b'MAC: ').split()[1])

        padlen = 16-len(plain)
        plain += bytes([padlen]*padlen)

        p.sendlineafter(b'Enter your choice: ', b'2')
        p.sendlineafter(b'Enter message in hex: ', enhex(plain).encode())
        mac_msb = unhex(p.recvline_startswith(b'MAC: ').split()[1])

        mac_guess = unbits(bits(mac_msb)[1:] + [0] + bits(mac_lsb))

        p.sendlineafter(b'Enter your choice: ', b'2')
        p.sendlineafter(b'Enter message in hex: ', enhex(bytes(16) + plain).encode())
        mac_last = p.recvline_startswith(b'MAC: ').split()[1]

        p.sendlineafter(b'Enter your choice: ', b'3')
        p.sendlineafter(b'Enter message in hex: ', enhex(plain + mac_guess + plain).encode())
        p.sendlineafter(b'Enter MAC in hex: ', mac_last)

        line = p.recvline().rstrip().decode()
        if 'SEKAI{' in line:
            p.success(line)
            break
