# encrypt.life-python
A simplistic prototype of encrypt.life in python. Focus has been on the QC-MDPC part, not the protocol. You may find vulnerabilities in the current implementation. Also, because of the numpy FFT, prime power is not used.

# High-level description of the desired final result

##The sender side
![protocol sender](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/sender.png)

##The receiver end
![protocol receiver](https://raw.githubusercontent.com/grocid/encrypt.life-python/master/receiver.png)

#Academic papers
[MDPC-McEliece: New McEliece Variants from
Moderate Density Parity-Check Codes](https://eprint.iacr.org/2012/409.pdf)