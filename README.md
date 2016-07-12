# encrypt.life-python
This is a simplistic prototype of [encrypt.life](http://encrypt.life) in Python. It is not production ready and should not be used in a real-life context. 

In this prototype, the focus has mainly been on making the QC-MDPC part efficient and not the actual protocol. Hence, you may find vulnerabilities in the current implementation of the protocol. Also, the primitives used in the code are not the ones mentioned below. This prototype uses:

* AES-256(m, k, iv) as symmetric cipher,
* SHA-256(token + salt) as PBKDF2,
* A truncated SHA-512(token + salt) for iv.

The final product will use Salsa-20 as symmetric-cipher primitive and Poly1305 for authentication purposes. Moreover, PBKDF2 or similar will be used for key generation.

Speed-ups in the decoding use the fast fourier transform (FFT) to achieve O(n log n) complexity in modular polynomial multiplications, instead of O(n²). Because the FFT implementation in Numpy is restricted to certain lengths (multiples of powers of 2), prime-power block length is not used (of course, in the final product prime-power block length will be used). See below for known vulnerabilities.

Below are given the proposed parameters for rate R = 1/2.

| Public-key size | Private-key size |  Rate          | Error weight  | Bit security |
| ---------------:|-----------------:| --------------:|--------------:|-------------:|
|      4801       | 9602             |     1/2        |     84        |   80         |
|      9857       | 19714            |     1/2        |     134       |    128       |
|       32771     | 65542            |     1/2        |     264       |   256        |
 
Since the encrypted token is a codeword of length 9602 (for 80-bit security), we add approximately 1200 bytes of data to the ciphertext. Apart from this, a 32-byte MAC is included. This inflates a (padded) message of size M to size 1232 + M. For higher security levels, the inflation will be larger — but still constant.

# High-level description of the desired final result

###The sender side

In this section, we will briefly describe the protocol. Much like a Fujisaki-Okamoto transform, it contains both an asymmetric part and a symmetric one. Consider the following scenario. Assume that Bob wants to send Alice a message. Denote Alice's keypair (pubkey, privkey). Bob takes the following steps: 

```
1. Bob picks a random token T.
2. He then uses Alice's public key denoted pubkey and encrypts the token T using QC-MDPC McEliece.
3. The token T is used to generate the symmetric key k₁ and the MAC key k₂ (PBKDF2).
4. The error vector used in the second step is concatenated with the message and a MAC is generated using k₂.
4. The message and the MAC are then encrypted with the symmetric key k₁.
5. The ciphertext is the concatenation of the encrypted token and encrypted message + MAC.
```

The ciphertext can now be distributed to Alice, using arbitrary means of communication. Below is a graphical interpretation of the above steps.


![protocol sender](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/sender.png)

###The receiver end

Now Alice wants to decrypt the message sent by Bob. She performs the following steps in order to do so:

```
1. Alice decrypts the encrypted token T using her private key privkey. In the decryption, the error vector is determined.
2. Using the decrypted token T, she derives the same symmetric key k₁ as Bob and decrypts the message.
3. The message and the MAC are extracted.
4. The MAC of the message and error vector is verified using the key k₂ derived from the token.
5. If the verification returns True, Alice accepts the message. Otherwise she rejects it.
```

This completes the outline of the protocol. Below is a graphical interpretation of the above steps.

![protocol receiver](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/receiver.png)

##Possibile vulnerabilities

###Decryption oracle
The protocol can be designed using normal McEliece or Niederreiter. In case of McEliece, the error vector should be part of the authentication (for instance, generate MAC using a concatenation of message and error vector). Such a measure will mitigate the usual decryption oracle attack, described below.

```
1. Intercept an encrypted message.
2. Pick a random bit of the ciphertext.
3. Flip it. If decryption fails, this was not an error position.
4. Repeat until all error positions have been unraveled.
```

Obviously, there is an implicit assumption that the receiver will either reject any error larger than T or the decoder will fail (which is rarely the case).

If the protocol instead is designed using the Niederreiter model, the error vector will be/encode the token. In this case, there is no need to authenticate the error vector. Since any flipped bit in the ciphertext will cause the receiver to decode a different token, it will break the decryption oracle.

###Timing attacks

This is a slight variation of the above. Instead of observing decryption errors, we measure the timing. There has been some effort in making decoding run in constant time. See [this paper](http://www.win.tue.nl/~tchou/papers/qcbits.pdf).

The decoding we use is probabilistic and susceptible to timing attacks. However, in the PGP-like setting we do not worry too much about this.

###Distinguishing attacks

The simplest imaginable distinguisher will detect a constant-error encryption with probability 1. 

```
1. Pick a ciphertext block with block weight l and error weight w.
2. Sum all symbols mod 2 and check if it equals (l + w) mod 2.
```

The theory is described in more detail [here](https://grocid.net/2015/01/28/attack-on-prime-length-qc-mdpc/). There is an easy counter-measure; we can thwart this attack completely by picking the error weight odd with probability 1/2:

```
1. Flip a balanced coin.
2. If the coin shows tails, pick a position at random and flip it.
```

This attack is contained in [distinguisher.py](https://github.com/grocid/encrypt.life-python/blob/master/distinguisher.py).

###Squaring/subcode attacks

Squaring attacks exploit that (the now deprecated) p = 4800 = 2⁶ × 75. By squaring the polynomial, the vector space decreases in size by a factor 2 (which can be done six times). It may also lead to collisions in the error vector, causing a decrease in error weight. This allows an attacker to go quite far below 80-bit security. See [this paper](http://link.springer.com/article/10.1007/s10623-015-0099-x).

This attack can be mitigated by picking a prime block length p. In the example above, p = 4801.

#Academic papers
[MDPC-McEliece: New McEliece Variants from Moderate Density Parity-Check Codes](https://eprint.iacr.org/2012/409.pdf)

[Lightweight Code-based Cryptography: QC-MDPC McEliece Encryption on Reconfigurable Devices](https://www.date-conference.com/files/proceedings/2014/pdffiles/03.3_1.pdf)

[Squaring attacks on McEliece public-key cryptosystems using quasi-cyclic codes of even dimension](http://link.springer.com/article/10.1007/s10623-015-0099-x)

#Acknowledgements
Miroslav Kratochvil (creator of [codecrypt](https://github.com/exaexa/codecrypt)) for pointing out a weakness in the protocol.