+++
title = "Writeup: zer0pts CTF 2022"
publishDate = 2022-03-20T12:00:00+00:00
+++

- Website: https://2022.ctf.zer0pts.com/
- CTFTime: https://ctftime.org/event/1555

## Anti-Fermat (crypto, warmup)

> I invented Anti-Fermat Key Generation for RSA cipher since I'm scared of the
> [Fermat's Factorization Method](https://en.wikipedia.org/wiki/Fermat's_factorization_method).
>
> [files](anti-fermat/anti_fermat_b8b9ddc83b728c86db324bd10da2242b.tar.gz)

This task implements textbook RSA, but with some special key generation:

```
# Anti-Fermat Key Generation
p = getStrongPrime(1024)
q = next_prime(p ^ ((1<<1024)-1))
n = p * q
e = 65537
```

It generates a (strong) 1024-bit prime `p` as usual. Then it generates `q` as
the first prime number that follows the binary inverse of `p`.

This means that every bit posistion (except for some low-order bits) will be set
in exactly one of `p` and `q` (that is, `p XNOR q` is zero except for some
low-order bits). Furthermore, since a bit can only be set in one of `p` or `q`,
assuming `p > q` (which implies that `p` has its 1024th bit set), the order for
all possible values of `p * q` is the same as the order of the values of `q`.

In other words, if we "move" a bit from `p` to `q`, we get a larger number. This
lets us leak each bit position (except for some low-order bits, but we can brute
force those).

We start off with `p` as all 1's (except for some 20 low-order bits) and `q` as
zero.

```
p = ((1<<1024)-1) ^ ((1<<20)-1)
q = 0
```

Then, for each bit position from 1023 down to 20, we check if the value of `(p ^
1<<bit) * (q ^ 1<<bit)` is smaller than the challenge `n`. If the product is
smaller than `n`, then we "move" the bit from `p` to `q`).

```
for i in range(1022, 19, -1):
    cur = 1<<i
    if (p^cur) * (q^cur) < n:
        p ^= cur
        q ^= cur
```

After this, we can be confident we have the top 1024-20 bits of `p`. Run an
exhaustive search for the remaining 20 bits, and decrypt `c` to obtain the flag.

```
while n%p != 0:
    p = gmpy2.next_prime(p)
q = n//p

d = gmpy2.invert(0x10001, (p-1) * (q-1))
print(long_to_bytes(pow(c, d, n)).decode())
```

```
$ time ./solve.py
p = 153456316755201256456077648680293404551531181234956990242779099773886170192558263224753907666532907469313954439789378399786631549347700474488574017322863270205683350905558827922567834954626909259763623105532668671134932118937640401627676913585506492102157561689678418157863742997375967679975824876706628973287
q = 26312996731030334316852870398609068810266516659273667030650981383846505612942699907954569655874628551806159440082014957872158219466716148004273413316610854172084542519306657353734384646619184859689459846552337097703218563404822479846236196955320745061192948994907880082083502941103748624859531452917595165959
Good job! Here is the flag:
+-----------------------------------------------------------+
| zer0pts{F3rm4t,y0ur_m3th0d_n0_l0ng3r_w0rks.y0u_4r3_f1r3d} |
+-----------------------------------------------------------+

real    0m14.728s
user    0m14.724s
sys     0m0.004s
```

[solve.py](anti-fermat/solve.py)

## MathHash (misc)

> I invented a very fast yet secure hash algorithm!
>
> `nc misc.ctf.zer0pts.com 10001`
>
> [files](mathhash/mathhash_3ec57fae465bf3e9c54a3b9782ce8ae6.tar.gz)

The server has a hash function `MathHash`, which is fed with `flag + input`.
Thus, we need to leak information about the flag in the hash output.

The hash function in question is like so:

```
def MathHash(m):
    hashval = 0
    for i in range(len(m)-7):
        c = struct.unpack('<Q', m[i:i+8])[0]
        t = math.tan(c * math.pi / (1<<64))
        hashval ^= struct.unpack('<Q', struct.pack('<d', t))[0]
    return hashval
```

The hash function takes `tan(pi * c/1<<64)` for a rolling 8-byte window (taken
as little-endian 64-bit unsigned integer) and XORs the resulting double into the
hash output.

Since the 8-byte window is unpacked in little-endian, the last byte in the
window is most significant. The `tan` result is XORed such that the most
significant byte in the double is XORed into the most significant byte of the
output.

For reference, a double is stored in memory like so[^mathhash-double-memory]:

[^mathhash-double-memory]: https://en.wikipedia.org/wiki/Double-precision_floating-point_format

![Double-precision floating point memory](https://upload.wikimedia.org/wikipedia/commons/a/a9/IEEE_754_Double_Floating_Point_Format.svg)

Now, with lots of trial and error, we discover that the last byte of each 8-byte
window is correlated with the most-significant byte of the `tan` output. In
fact, we notice that for the range of values we need to deal with, exactly one
of the 6th or 7th bit of the most-significant byte in the `tan` output is set. A
notable exception is when the input is all zeroes, in which case the `tan`
output is also zero.

This means that we can look at the 6th and 7th bits changing in the hash output
to check whether we successfully guessed the hash output.

Starting with the 7 known bytes (`zer0pts`), we make a guess for the next
character, and send an input such that it sums to 0 with the flag. If we guessed
correctly, exactly one of the 6th or 7th bits should have flipped. Repeat this
until we obtain the entire flag.

```
$ ./solve.py
[+] Opening connection to misc.ctf.zer0pts.com on port 10001: Done
[*] zer0pts{
[*] zer0pts{s
[*] zer0pts{s1
[...]
[*] zer0pts{s1gn+|3xp^|fr4c.}
[+] zer0pts{s1gn+|3xp^|fr4c.}
[*] Closed connection to misc.ctf.zer0pts.com port 10001
```

[solve.py](mathhash/solve.py)
