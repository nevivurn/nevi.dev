#!/usr/bin/env python3

from pwn import *

c = remote('chals.damctf.xyz', 30888)

challenge = c.recvline().split()[-1]
with log.progress('solving proof-of-work', challenge.decode()) as progress:
    challenge = b64d(challenge)
    while True:
        rnd = bytes(random.getrandbits(8) for _ in range(16))
        digest = sha256sum(challenge + rnd)
        if not digest.startswith(b'\x00' * 3):
            continue
        c.sendline(b64e(rnd))
        break
    progress.success('done')

with open('american-english') as f:
    words = [word.rstrip() for word in f if all(ord(c) < 128 for c in word)]
    shuffle(words)
word_groups = list(reversed(group(64, words)))

known = []

def check_words(c, words):
    c.sendlineafter('Enter a menu option number:', '1')
    for word in words:
        c.sendline(word)
    c.send(b'\n')

    c.recvuntil('---BEGIN RESPONSE---')
    data = c.recvuntil('---END RESPONSE---')

    log.info('%s: %s', len(words), len(data) > 19)
    return len(data) > 19

def find_word(c, words, skip=False):
    if not skip and not check_words(c, words):
        return
    if len(words) == 1:
        return words[0]

    half = len(words) // 2
    first = find_word(c, words[:half])
    if first:
        return first
    return find_word(c, words[half:], skip=True)

while len(known) < 10:
    cur_words = word_groups.pop()

    word = find_word(c, cur_words)
    if word:
        log.success('success: %s', word)
        known.append(word)

log.success('words: %s', known)
c.sendlineafter('Enter a menu option number:', '3')
c.sendlineafter('Enter ten words from our dictionary sample, seperated by spaces:', ' '.join(known))

log.success(c.recvall())
