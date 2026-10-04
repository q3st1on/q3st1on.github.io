+++
date = '2026-08-23T20:58:52+08:00'
draft = false
tags = ['crypto']
title = 'Overlooked: The CBC-R attack'
+++

## Introduction

Back in November of 2023 I found out about a 13-year-old basic padding oracle attack that was somehow completely new to me. A CBC padding oracle technique which I had not encountered before in a paper, a ctf, or CryptoHack. Thinking it was surely common knowledge I went to find a library that would do the work for me (yes, I know, I'm lazy) and found to my amazement none of the libraries I checked (tbf: all Python) even mentioned it.

Realising I had to actually put in effort, I made my own implementation and went on about my day. With this still bugging me a week later, I decided to throw my code at a Python library[^1] and move on.

Since then, I have kept an eye out for the technique and have seen quite literally nothing. To be clear, it's not that people *don't know* about CBC-R, but for a budding young hacker, it's unlikely they will stumble across it and *learn* of the attack.

### Background

The scenario I first saw this in was a PHP (:thumbsdown:) website that used AES-CBC encryption for its session cookies, and then trusted flags from the decrypted cookie contents to verify a user's privilege. The cookie plaintext was constructed as `SERVER-SECRET | &role=ROLE&user=USERNAME&time=LOGIN TIMESTAMP`. This looked relatively easy; however, I soon realised the `&role=ROLE` field was absent from the token my lowly user account was given and the site simply defaulted to the `USER` role if the field was missing.

## The good, the bad, the boring: CBC

*If you already understand CBC padding oracle attacks, skip to [CBC-R: encryption oracles for free?](#cbc-r-encryption-oracles-for-free)*

### CBC Encryption

![CBC Encryption Diagram](/images/cbc-encryption.svg)

CBC encryption follows the general process described above. For encryption function $E$ and key $K$, the plaintext $P$ is split into $n$ blocks of size $s$ bytes and each block is encrypted to form the ciphertext $C$ block such that

$$
C_i = E_K(P_i) \oplus C_{i-1}, \forall i \in {1, n}
$$

where $C_0$ is the initialisation vector $IV$, a 1-block long random string.

This leads to a requirement that the length of plaintext $P$ is a multiple of $s$ or the final block will not have enough bytes to complete the XOR step. The solution to this is a padding system which fills the remaining bytes of the final block in some deterministic manner such that you can easily determine which bytes are these 'junk' padding values and remove them again after decryption.

While there are many padding standards, one of the most common, and the one you should consider for this explanation, is a standard called PKCS#7 padding. PKCS#7 padding fills the remaining bytes with each byte set to the number of bytes padding used. If the plaintext is already a multiple of the block size, a whole block of padding is used.

### CBC Decryption

![CBC Decryption Diagram](/images/cbc-decryption.svg)

CBC decryption follows a similar structure, such that for decryption function $D$ and key $K$:

$$
P_i = D_K(C_i) \oplus C_{i-1}
$$

### CBC Padding Oracles [^2]

You may have noticed I added an `intermediate` as a labeled part of the decryption graph, where intermediate $I_i = D_K(C_i)$. The goal of a padding oracle attack is to use knowledge of whether your submitted ciphertext decrypted to produce valid padding, and control of the previous ciphertext block, to reconstruct those intermediate values byte-by-byte.

You can observe that if we replace the preceding block with an altered value $C^\prime_{i-1}$ the decrypted value of the target block becomes

$$
P^\prime_i = D_K(C_i) \oplus C^\prime_{i-1}
$$

Consider that the XORing of two blocks occurs byte-by-byte for bytes $1$ to $s$. It therefore is possible to recover the intermediate form of the final byte in the target decryption block by trying all 256 possible byte values and proceeding till one produces the valid form of single byte padding ($\texttt{0x01}$ in PKCS#7):

$$
I_i[-1] = C^\prime_{i-1}[-1] \oplus \texttt{0x01}
$$

The attacker can then set the value of $P\prime_i[-1]$ to $\texttt{0x02}$ and try again, testing values till $P\prime_i[-2]$ is also $\texttt{0x02}$ and the padding is correct. This continues back to the starting byte of the message (if the attacker controls the $IV$) or otherwise decrypts back to the 2nd block in the message.

Once the whole message has been recovered in intermediate form, it is trivial to run the XOR forward from the $IV$ (or $C_0$) to get the plaintext as:

$$
P_i = I_i \oplus C_{i-1}
$$

This is the padding oracle attack, turning a seemingly useless bit of side-channel information into a decryption oracle for the discerning attacker.

## CBC-R: encryption oracles for free?

The CBC-R attack was published by Juliano Rizzo and Thai Duong in 2010 [^3], and was the attack that (despite getting a section on the Wikipedia page for padding oracles) I first encountered in 2023.

Consider an attacker that has recovered the whole intermediate form $I$ of a block where $I_i = D_K(C_i)$. They can take a new plaintext block $P^\prime$ and forge a valid ciphertext $C^\prime$ for it as follows:

$$
C^\prime_{i-1} = I_i \oplus P^\prime_i
$$

The power of this attack comes from the fact that, with control of the $IV$, the attacker can from a starting $C_i$ of pure random noise construct the ciphertext for their chosen message by successively calculating the $C^\prime_{i-1}$ block that will give them their chosen decryption.

This attack, without touching the actual cryptosystem in use, or revealing the key, enabled the forging of complete valid ciphertexts of arbitrary contents and length. It flips our decryption oracle to an encryption one.

> [!NOTE]
> **We don't talk about bit-flipping**
>
> The astute reader may notice that if they need to alter the plaintext value of block $C_i$ they can simply flip bits in $C_{i-1}$ to force the value they want in plaintext block $P_i$. This is true (and one of the reasons why you should use a block cipher mode that provides AEAD if possible), however, it is far less powerful than the CBC-R attack. Firstly, in doing a bit-flipping attack you corrupt the plaintext of block $C_{i-1}$, and secondly it requires an existing valid ciphertext of the right length and knowledge of its plaintext structure to usefully exploit it.
>
> (You also need to hope your target region is not across multiple blocks or it can be *painfully* finicky)

### How it helped me

When I was dealing with that PHP (:thumbsdown:) website this attack proved invaluable as I couldn't alter the previous block without corrupting that server secret. I first recovered `SERVER SECRET` from my cookie (why was it shared? I don't know) then used CBC-R to build a valid ciphertext with `&role=ADMIN` from scratch.

### Where this attack is *actually* helpful

This attack really shines for its ability to completely expose whatever attack surface sits *after* the decryption of your ciphertext. If there happens to be a juicy bug like insecure deserialisation sitting in the code which receives the plaintext, CBC-R gives you complete freedom as to the payload you send through.

This is not *complete* speculation on my part. Back in the simpler time of 2019, a rather fun 2-bug RCE chain `Shiro-721` was discovered in the open source security framework Apache Shiro.[^4] The chain used a padding oracle attack on the `rememberMe` cookie + CBC-R to enable an attacker to craft an insecure deserialisation payload that would, when passed back in the HTTP headers, be decrypted and subsequently detonate on the server.

## Conclusion

While the relevance of this technique has certainly lessened over time as more and more systems adopt message authentication techniques which ensure a value hasn't been altered, I do still feel it is a shame this technique isn't really demonstrated or taught much because it's downright fun.

If you happen to be making a crypto workshop, CTF challenge, class, or anything else where you think bringing up padding oracles is appropriate, consider throwing CBC-R a bone. If anything, it might help remind folks both that encryption $\ne$ authentication, that *all* the code should be secure, and *no external input should be trusted*.[^5]


[^1]: [PyPI: padding-oracle](https://pypi.org/project/padding-oracle/)
[^2]: [Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS...](https://link.springer.com/chapter/10.1007/3-540-46035-7_35)
[^3]: [Practical Padding Oracle Attacks](https://www.usenix.org/legacy/events/woot10/tech/full_papers/Rizzo.pdf)
[^4]: [issues.apache.org/jira/browse/SHIRO-721](https://issues.apache.org/jira/browse/SHIRO-721)
[^5]: [Obligatory XKCD](https://xkcd.com/327/)