# encrypt.life-python
A simplistic prototype of encrypt.life in python. Focus has been on the QC-MDPC part, not the protocol. You may find vulnerabilities in the current implementation. Also, because of the numpy FFT, prime power is not used.

| Public-key size| Private-key size |  Rate         | Error weight  | Bit security |
| ---------------|:----------------:| -------------:|--------------:|-------------:|
| 4801           | 9602             |     1/2       |     84        |   80         |
| 9857           | 19714            |     1/2       |      134      |   128        |
| 32771          | 65542            |     1/2       |     264       |   256        |

# High-level description of the desired final result

##The sender side
The protocol is based on Fujisaki-Okamoto

![protocol sender](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/sender.png)

###Possibile vulnerabilities

#####Decryption oracle
The protocol can be designed using normal McEliece or Niederreiter. In case of McEliece, the error vector should be part of the authentication (for instance, generate MAC using a concatenation of message and error vector). Such a measure will mitigate the usual decryption oracle attack, described below.

```
1. Intercept an encrypted message.
2. Pick a random bit the ciphertext.
3. Flip it. If decryption fails, this was not an error position.
4. Repeat until all error positions have been unraveled.
```

Obviously, there is an implicit assumption that the receiver will either reject any error larger than T or the decoder will fail (which is rarely the case).

If the protocol instead is designed using the Niederreiter model, the error vector will be/encode the token. In this case, there is no need to authenticate the error vector, since any flipped bit in the cipher text will cause the receiver to deocde a different token, hence breaking the decryption oracle.

#####Timing attacks

This is a slight variation of the above. Instead of observing decryption errors, we measure the timing. There has been some effort in making decoding run in constant time. See [this paper](http://www.win.tue.nl/~tchou/papers/qcbits.pdf).

The decoding we use is probabilistic and susceptible to timing attacks. However, in the PGP-like setting we do not worry too much about this.

#####Distinguishing attacks

The simplest imaginable distinguisher will detect a constant-error encryption with probability 1. 

```
1. Pick a ciphertext block with block weight l and error weight w.
2. Sum all symbols mod 2 and check if it equals (l + w) mod 2.
```

The theory is described in more detail [here](https://grocid.net/2015/01/28/attack-on-prime-length-qc-mdpc/).

We can thwart this attack completely by picking the error weight odd with probability 1/2:

```
1. Flip a balanced coin.
2. If the coin shows tails, pick a position at random and flip it.
```

#####Squaring/subcode attacks

Squaring attacks exploit that (the now deprecated) p = 4800 = 2⁶ × 75. By squaring the polynomial, the vector space decreases in size by a factor 2 (which can be done six times). It also causes collisions in the error vector, making it to decrease in weight. This allows an attacker to go quite far below 80-bit security. See [this paper](http://link.springer.com/article/10.1007/s10623-015-0099-x).

This attack is mitigated by picking a prime block length p. In the example above, p = 4801.

##The receiver end
![protocol receiver](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/receiver.png)

#Academic papers
[MDPC-McEliece: New McEliece Variants from Moderate Density Parity-Check Codes](https://eprint.iacr.org/2012/409.pdf)

[Lightweight Code-based Cryptography: QC-MDPC McEliece Encryption on Reconfigurable Devices](https://www.date-conference.com/files/proceedings/2014/pdffiles/03.3_1.pdf)

[Squaring attacks on McEliece public-key cryptosystems using quasi-cyclic codes of even dimension](http://link.springer.com/article/10.1007/s10623-015-0099-x)

#Acknowledgements
Miroslav Kratochvil (creator of [codecrypt](https://github.com/exaexa/codecrypt)) for pointing out a weakness in the protocol.