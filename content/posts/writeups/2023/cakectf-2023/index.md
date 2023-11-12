+++
title = "Writeup: CakeCTF 2023"
math = true
publishDate = 2023-11-12T09:13:04+00:00
+++

- Website: https://2023.cakectf.com/
- CTFTime: https://ctftime.org/event/1973

I participated in the team "bacchus-snu", along with my teammates.

## simple signature

> It must be a piece of cake. `nc crypto.2023.cakectf.com 10444`
>
> [simple_signature_35e417a8d6d7aa91284410725e4fa651.tar.gz](simple-signature/simple_signature_35e417a8d6d7aa91284410725e4fa651.tar.gz)

We need to forge a signature for the message `cake_does_not_eat_cat`. That is,
we need to produce $s, t$ for which $s^w t^{-v} = g^m$.

If we let $s = g^a$ and $t = g^b$, then the signature verification scheme looks
like $g^{aw} g^{-bv} \equiv g^m \pmod{p}$, or equivalently, $aw - bv \equiv m
\pmod{p-1}$.

From the key generation, we have $v = wy \pmod{p-1}$, so we now have $w(a - by)
\equiv m \pmod{p-1}$. We know the values of every variable except $y$, which we
can compute as $y \equiv vw^{-1} \pmod{p-1}$.

We can now forge the signature by choosing $a = w^{-1}m + 1$ and $b = y^{-1}$.
This works because:

$$
\begin{align*}
  aw-bv &= w(a-by) \\\
  &= w(w^{-1}m + 1 - y^{-1}y) \\\
  &= m
\end{align*}
$$

We then send $\mathtt{"cake\\_does\\_not\\_eat\\_cat"}, g^a, g^b$ and obtain the
flag.

```
$ ./solve.py
[+] Opening connection to crypto.2023.cakectf.com on port 10444: Done
[*] Switching to interactive mode
verified
flag = CakeCTF{does_yoshiking_eat_cake_or_cat?}
[*] Got EOF while reading in interactive
$
[*] Closed connection to crypto.2023.cakectf.com port 10444
```

[solve.py](simple-signature/solve.py)

## ding-dong-ting-ping

> `nc crypto.2023.cakectf.com 11111`
>
> [ding-dong-ting-ping_401ca3c429f9c767351e9ba3ff17b830.tar.gz](ding-dong-ting-ping/ding-dong-ting-ping_401ca3c429f9c767351e9ba3ff17b830.tar.gz)

First, we determine the secret prefix length, which turns out to be 17 bytes.
This means we need to forge a ciphertext that decrypts to something that looks
like `?????????????????|user=root|${DATE}`. Split into 16-bytes blocks, this
looks like `["????????????????", "?|user=root|date", "|..."]`. We achieve this
as follows:

1. Register with the username `"room|date"` (or any other 9-character username),
   obtaining ciphertext `IV || c0 || c1 || ...`.
   - This corresponds to the plaintext blocks `["????????????????",
     "?|user=room|date", "2023..."`.
   - `c1` corresponds to the second plaintext block, which was XORed with
     `MD5(c0)` before encryption.
2. Register with the username `"room|date" || XOR(MD5(c0), MD5(c1),
   "?|user=root|date")`, obtaining the ciphertext `IV || c0 || c1 || c2 || ...`.
   - The ciphertext blocks up to `c1` are the same, because the early plaintext
     blocks have not changed.
   - `c2` corresponds to the third plaintext block, which was XORed with
     `MD5(c1)` before encryption.
   - That is, just before encryption, this block looks like `XOR(MD5(c0),
     "?|user=root|date")`.
3. Log in with the ciphertext `IV || c0 || c2...`.
   - When the server decrypts `c2`, it XORs the resulting plaintext with
     `MD5(c0)`, resulting in `"?|user=root|date"`.

We don't know the value of the secret prefix, but we only need to guess its last
byte. We repeat steps 2-3 for every possible value of the prefix, and we obtain
the flag.

```
$ python solution.py
[+] Opening connection to crypto.2023.cakectf.com on port 11111: Done
[+] guess: Done
[*] Switching to interactive mode
Ding-Dong, Ding-Dong, Welcome, root. The ultimate authority has logged in.
This is for you =>  CakeCTF{dongdingdongding-dingdong-dongdingdong-ding}

===== MENU =====
[1]register [2]login: $
[*] Closed connection to crypto.2023.cakectf.com port 11111
```

[solve.py](ding-dong-ting-ping/solve.py)
