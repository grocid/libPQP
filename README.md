# encrypt.life-python
This is a simplistic prototype of [encrypt.life](http://encrypt.life) in Python. It is not production ready and should not be used in a real-life context. 

In this prototype, the focus has mainly been on making the QC-MDPC part efficient and not the actual protocol. Hence, you may find vulnerabilities in the current implementation of the protocol. Also, the primitives used in the code are not the ones mentioned below. This prototype uses:

* AES-256(m, k, iv) as symmetric cipher,
* SHA-256(token + salt) as PBKDF2,
* A truncated SHA-512(token + salt) for iv.

The final product will use Salsa-20 as symmetric-cipher primitive and Poly1305 for authentication purposes. Moreover, PBKDF2 or similar will be used for symmetric-key generation.

Speed-ups in the decoding use the fast fourier transform (FFT) to achieve O(n log n) complexity in modular polynomial multiplications, instead of O(n²). Because the FFT implementation in Numpy is restricted to certain lengths (multiples of powers of 2), we use [pyfftw](https://pypi.python.org/pypi/pyFFTW) which is a wrapper for [FFTW3](https://github.com/FFTW/fftw3). FFTW3 implements Winograd's FFT algoritm and supports prime-length blocks. See below for known vulnerabilities.

Below are given the proposed parameters for rate R = 1/2.

| Public-key size | Private-key size |  Rate          | Error weight  | Bit security |
| ---------------:|-----------------:| --------------:|--------------:|-------------:|
|      4801       | 9602             |     1/2        |     84        |   80         |
|      9857       | 19714            |     1/2        |     134       |    128       |
|       32771     | 65542            |     1/2        |     264       |   256        |
 
Since the encrypted token is a codeword of length 9602 (for 80-bit security), we add approximately 1200 bytes of data to the ciphertext. Apart from this, a 32-byte MAC is included. This inflates a (padded) message of size M to size 1232 + M. For higher security levels, the inflation will be larger — but still constant.

# High-level description

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

##Key format

The keys are encoded in Base64 and ASN.1, just like the normal ascii-armored keys used in public-key cryptography. The public-key structures contains only the generator polynomial G.

```
class ASN1PublicKey(pyasn1.type.univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('G',     pyasn1.type.univ.BitString())
    )
```

A typical (encoded) public key has the following appearance:
```
-----BEGIN PQP PUBLIC KEY-----
MIICXgOCAloHWr9hpRqoFb0C27x8w1/1hYHY7DQmAgevQaTWb13mNlCgYDsrVO3WHSTRY7Owt7Ab
tCUhuHxC9zK9tmC7yzyO7I9e0bj7db8FmxpOM5B+TfRruQwChiUn67yY8/vjuX3U+MHS973TNxUD
Sef9cSepiHLydGnvFKWaastnBI8AJilPddH2sABHRDAENHFutZjfoXHfaMfC85sLLDCjLLS7fBxr
4FB3sihOzbvhbBUg9AdaPmL1wcTz3Z4tjbLHjd62g9uX3aHx3bm0uHWQ2IpG/n01o4yoXzCdZ1xu
Ud04B6n6HzTWSFzvNUdpJ7lmJnNzX/puwqxFBts7d2SMRVthaGJktF69pQkGP3xi1Axg579Rk/pc
RW6m9R6n2VyrU81kcAqaAWFrsVcoBmC5UH4r7vmvHcJG5mQPCPjPxo/B0PA3atwOpmtNZqcoRDcC
J030i4atAizFB+tixzMKYqFX55CP81tQQx1G/FbDFjQkWmiPc0Xl1Ua2lJhD9kJ3ZgvhCpjFrZmG
mQkxmg93OmyGr0PJldt1wGrb/Gi6q892fenOPIUdmBCPDbUHpn6VxgLoMVeywOsplHwRptA0uN3r
nprT5+0yarHC7Evue1OQHLe3rG34BzA0uLsDdphyy9F2c56udqElbNssbmNtn6yN+VDH9Z6Ceq7B
LbqIBZCxe3Tner5vJ+Vc52bZ6s71dbQ/0ZBN/EGDI8geGWXXtdoySloQgJ6vAiJAAcB6uz52buNi
hYXGud3x9djrJq65wHa/gL3lUSoYpsvZ8xdue6127IQ54DJ9m4qBAA==
-----END PQP PUBLIC KEY-----
```

The private key contains the two secret-key polynomials H₀ and H₁. Because inversion takes quite a while to perform, the inverse of H₁ is also contained in the private-key structure:


```
class ASN1PrivateKey(pyasn1.type.univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('H0',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('H1',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('H1inv', pyasn1.type.univ.BitString()),
    )
```

Below is a typical private key given. As we can see, the elements H₀ and H₁ are very sparse. These polynomials could be encoded more efficiently, but we don't care too much about private-key size and is therefore left as is.

```
-----BEGIN PQP PRIVATE KEY-----
MIIHGgOCAloHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAA
AAAAAAAAAAIAAAAAAAAAEAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAA
AAACIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAABAAAAAAAACAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAABAAAAAAAAAAABAAAAAAAAAAACAAAAAAAAAAAAAAAAAEAAAEAAAAAAAEAIAQAAAAAAABACAA
AAAAAEAABAAAAAAAAAAAAAAAAAAgAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAABBAAAAAAAAA
AAAAAAAAAAAACAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAACAAAAAAAAACAAAAAAAAAIA
AASAAAgAAAAAAAAAAAQAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAACAAAABAAAOCAloHAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAABAAAAAAAAABAAAAAAAAAAACAAAAAAAAAAAAEAAA
AAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAIAAAIAAAAAgAAEAAAAAAAAAAAAAAAAAACAAAAAAAAAA
EAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAIAAAAAAAQ
AAAAAAAAADAAAAAAAAAAAAAAAAAAIAAAAAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA
AAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAIQAAAAAAACAAAAAAAAAAAA
gAAAAIAAAIAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAA
AAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAABAQAAAAAQAA
AAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAIAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAQ
ABAAAAAAAAAAAAAAAAAAAAAAAAOCAloHvDcNLTjcH126GZhJMH/p96Fx1mI+cIiTGSSXHiz4fJb1
zJWPSdpAhFNRfYUsFX29oP8CGQDVDY8mT1xujozLTN+BhYOL7XwO7877v8iyN8TBVfWYZOTlrnE6
4Q+kO0JhUvAx9P4BDgF8njezMa8dhTq8xZ7zeANEhbCp1yDNlCPGvfGuyLoTz9uXRrSYlKnFt96p
2S1V2rEFenIki/iAjCLjnGJtjV6UqvwpqB7F/q6VzLekXihE528GVYL2PyDoqRoV+TVPwlxhz6RV
n0yFQvOoQQtn549HsIsPKAQZF+hVyalioxk/1mmOAf860xgfTcPN0BsPoWXVjzuHgSy44qql5xGp
bgOVVVZeRUFh792z+Kj5NiaZL3p+JS09+/O5B9KFZUQJlQK3HBlxxnhPU78ki9mMuSMIufEvAb9S
9fa6anppzcv2FkyIsInmEqeZjnAuJqIV0GmW190GRWRZDYuqERzh5hBXD3MDZQhUCSAVc4PL4QRZ
UrCrDHynLEdmgiIAYEhx25Nhnp5bA7bVUqMHfWEs6NKdDhdno/hkBPlwl4ANcgmrqt77Ac5G1xzy
unpFXE9k6DXEMO1+Y1RcvRovXTK+CDXK2ALYdMW7O2GrPLyob3rEtIShmsDVYTJDM6eOnsRhlhyO
0MqnlljYpBfufcGvvUqR2iH9WbU4jBAt5qk0rEskidOnpPlwyd36kfH/z8BUYWST/gbhyKTJ7aBL
01tFT1hBLoFTa6X90FtypZU/y9Wg8VS07435kDZuYwJl6o1uzbRoOOfUmpnAwYfjJbwU6ervgA==
-----END PQP PRIVATE KEY-----
```
 
 The messages are structured in a similar way. The encrypted token is stored in C0 and C1 and the symmetric ciphertext and MAC are stored as OctectStings.
 
 ```
 class ASN1Ciphertext(pyasn1.type.univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('C0',    pyasn1.type.univ.BitString()),
         namedtype.NamedType('C1',    pyasn1.type.univ.BitString()),
         namedtype.NamedType('Sym',   pyasn1.type.univ.OctetString()),
         namedtype.NamedType('MAC',   pyasn1.type.univ.OctetString()),
     )
 ```
We encrypted the message 
```
this is a really secret message that is padded with some random.'
```
and put it into the ASN.1 format. Below is the ciphertext.
 
 ```
 -----BEGIN PQP MESSAGE-----
 MIIFIAOCAloHaaHbjcotpz7pyi2L4CRsg/gGpu3kSexB9w3a0Uiq8UmUGOe/3sm4/TsmbVA0xTQ2
 DuEg99v/L2Y+l6/xNsqKRC+ypDsWFgsfBDe5kwy5zBH0/6jAebrhz9fReIQlFXPR7QXLRgr+tLPM
 wd8eHsPAbiS6FD8hE5VRLMUg++EPCMgoSthHbUb5sGeidM/p+pLgIEj5ZSpbEMDCJJ9+2O0Ir2um
 roQB008xPf066aNPXkp/ADn/PxyKDbSwhybkLO3T6inQYAjA6xuq/LSkbq0oLu/c8urmDaNYiDOj
 BOjRMtYgm+/UKmkUhDSsgSGaENbYhrjS4y8KxZ/bBrObvX78FXGf+fuF4CoPr9S9X7YDAhn49E2i
 1LrjNUY6YxVb5YFctyQqThgHUKYworssdQFY95lafEaSe/xri3OIWJLnNmEQqLsCUHjqAaJOrEHV
 6dKTfdHLiOw1AL4zyBCcwBx5ixRstbAq+PyffimX9G/DNrWO2G9B0aJE4pXF6i4o12BNM7nA0Ejc
 AGYOGGnc5f7YM82YMfSVrMR7jkI4DchCRxPyfHpMy/BiIW/XzKSRv1aMOc+16YtCdL2AX9PCtc+x
 ob6XHcr87VQrDMPBmbbs0SFAB2H6hNT8YighnX9p8otyIzk8JCt76TZg1+0ax7r88wqDN4I8sOVa
 Opj/c6C50o4oOrthoRAZGatOBLLP4y6KbktwUjeuarAGCJ5429BECb8COdhLnkwUg6hZ6//rQGbI
 hGQyVE7xTFmDrSL8UT2z5KEt02jEm3tXkAkOx/USKspqa/OVBMZIAAOCAloH2TJ1NBiaN4TheYe3
 jA6oIwXTCLYK3t5VFqq8RpW7iU7rCIIIDX0/t86SZUc5OGVN9F9kkGJgefU7dPAK18fgEglrcLtO
 VNyfECs9OA0pl7NfPdof2DJRvZMgs492oSeo/b3xTG/JZDY2swCofB1q5cca/IergxDq1cGhEemG
 fuVzBZcCFR9YsLiS4un89jI/QnMRmTdo6MtR+FCWr7c5pcOiEYwTLX5+l3KB7AydE5OTIaXgdhLI
 ut0wO4fMrF08FN9Skn+0bfKz1gACbANce39eOnnMtH8Xo3TQ+L2DJQ7/tycp2vjyD+7YXI9YIHWp
 ds8VZkAm9rwCzop14ObhSCgaNU1ERg0kaA8WaQPPV33uLk7NyCF/XpW6T8baSUIs1Lk1Vw3Y2Tvg
 9cBICQYhjSnBcwHfIVD4N3SZXXZ9JQ5o18x7RY9XkdKFlIlgceefzY3llxbD+BucJlCREYHHpdQD
 03fUXUcEJovRisiavp8aD9ERZibliZq8TPIGhP8mhI8Lf2PaZdtSj810Av1iCDOdD3ncrVLH/wYk
 +xhGE5D8ipLj7kM1eX1eimr9N7uQCPyJRz+NM/heKPEusMojskWtt4jXK1UgutfgI7l1chMVcaOh
 gosuhtR+NJHfEnfUg/xIq9DpiaXHDw5VcrxmbJrqwx2Rd4V55pyYy4PGrpuzSxBh9BLqWFM5DwBq
 P3J8329KNdMLlYUE9Puz/MQZtwjuKMfYK7KRK6Yr3pyhUzQCEEniuzn+0LID8poW6I9O463rP7cU
 s6TqiVGZ3pGN4bNgd6KmBG2jAARAZN9cjlY/OZUvRYxrkJPCYd3mob/8FHjIZUp+HI+KhEuc9TlF
 NvocCfAZoAxs0v2f5tE2NSkrFhaLtl+3jJ//mAQgvHqfnrvWF6yDWflK9EijPkNskOXh5qX7UZHw
 Mh6VrwU=
 -----END PQP MESSAGE-----
  ```
 
##Possible vulnerabilities

###Decryption oracle
The protocol can be designed using normal McEliece or Niederreiter. In case of McEliece, the error vector should be part of the authentication (for instance, generate MAC using a concatenation of message and error vector). Such a measure will mitigate the usual decryption oracle attack, described below.

```
1. Intercept an encrypted message.
2. Pick a random bit of the ciphertext.
3. Flip it. If decryption fails, this was not an error position.
4. Repeat until all error positions have been unraveled.
```

Obviously, there is an implicit assumption that the receiver will either reject any error larger than T or the decoder will fail (which rarely is the case).

If the protocol instead is designed using the Niederreiter model, the error vector will be/encode the token. In this case, there is no need to authenticate the error vector. Since any flipped bit in the ciphertext will cause the receiver to decode a different token, it will break the decryption oracle.

###Timing attacks

This is a slight variation of the above. Instead of observing decryption errors, we measure the timing. There has been some effort in making decoding run in constant time. See [this paper](http://www.win.tue.nl/~tchou/papers/qcbits.pdf).

The decoding we use is probabilistic and susceptible to timing attacks. However, in the PGP-like setting we do not worry too much about this. Below is a graph of timings of my computer (Macbook Pro 15" Retina 2 GHz Intel Core i7) running 1000 decryptions using the same private key (σ = 0.0386, μ = 0.493):

![protocol receiver](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/timings.png)

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