#!/usr/bin/env python3

from pwn import *
import gmpy2
import socket
import sys

""" Client """

CHUNK = 10000

def to_bytes(p):
    return p.to_bytes((p.bit_length() + 7) // 8, "big")

# TODO: Generate Diffie-Hellman keys
def gen_key(a, g, p, B):
    A = gmpy2.powmod(g, a, p)
    KA = gmpy2.powmod(B, a, p)
    return int(A), int(KA)
    """
    Choose random a \in [1, p-2]
    find A: g ^ a mod p
    find KA: B ^ a mod p
    output: A, KA
    """

# TODO: Decrypt multiplication one-time pad
def otp_decrypt(key, p, ctext):
    """
    output: ctext * key^-1 mod p
    Hint: You will need to compute modular inverse
    """
    return int(ctext * gmpy2.invert(key, p)) % p


def run_client(*con):
    def receive_ints(s):
        received = s.recv(CHUNK).decode()
        print("Server:", received)
        try:
            parsed = [int(x) for x in received.strip("\n").split(",")]
        except ValueError:
            print("Client exiting")
            exit(1)
        return parsed

    keys = [0, 0]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(con)
        print(s.recv(CHUNK).decode())

        # Receive D-H parameters from the server
        generator, modulus, server_pkey = receive_ints(s)

        # Generate our D-H public key and shared key
        pkey1, ka_key1 = gen_key(2, generator, modulus, server_pkey)
        pkey2, ka_key2 = gen_key(3, generator, modulus, server_pkey)

        # The server will encrypt each plaintext with our keys
        keys[0] = pkey1
        keys[1] = pkey2
        formatted_keys = ','.join(str(key) for key in keys).encode()

        # Send keys to server
        s.send(formatted_keys)

        # Receive both ciphertexts from server encrypted with respective keys
        ctexts = receive_ints(s)

    # Decrypt the one ciphertext we can decrypt (as determined earlier by choice_bit)
    ptext1 = otp_decrypt(ka_key1, modulus, ctexts[0])
    ptext2 = otp_decrypt(ka_key2, modulus, ctexts[1])
    print("Decrypted text:")
    print(xor(to_bytes(ptext1), to_bytes(ptext2)))

    return 0

def main(argv):
    if len(argv) != 3:
        print(f"usage: ./{sys.argv[0]} host port")
        return 1

    host, port = argv[1:]
    return run_client(host, int(port))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
