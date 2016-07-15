from pyasn1.codec.der import encoder, decoder
import pyasn1.type.univ
import pyasn1.type.namedtype as namedtype
import base64

from keygen import *
from private_key import *
from public_key import *


class ASN1PublicKey(pyasn1.type.univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('G',     pyasn1.type.univ.BitString())
    )

class ASN1PrivateKey(pyasn1.type.univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('H0',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('H1',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('H1inv', pyasn1.type.univ.BitString()),
    )

class IO:
    
    def to_bitstring(self, vec):
        return pyasn1.type.univ.BitString('\'' + ''.join([str(x) for x in vec]) + '\'B')
    
    def extract_der_priv_key(self, seq):
        seq = seq.replace('-----BEGIN PQP PRIVATE KEY-----\n', '')
        seq = seq.replace('-----END PQP PRIVATE KEY-----\n', '')
        der = decoder.decode(base64.decodestring(seq), asn1Spec=ASN1PrivateKey())[0]
        priv_key = PrivateKey()
        priv_key.H_0 = np.array(list(der['H0']))
        priv_key.H_1 = np.array(list(der['H1']))
        priv_key.H_1inv = np.array(list(der['H1inv']))
        priv_key.block_length = len(priv_key.G)
        return priv_key

    def get_der_priv_key(self, pub_key):
        template = '-----BEGIN PQP PRIVATE KEY-----\n{}-----END PQP PRIVATE KEY-----\n'
        
        der = ASN1PrivateKey()
        der['H0'] = self.to_bitstring(priv_key.H_0)
        der['H1'] = self.to_bitstring(priv_key.H_1)
        der['H1inv'] = self.to_bitstring(priv_key.H_1inv)
        
        data = base64.encodestring(encoder.encode(der))
        return template.format(data)
        
    def extract_der_pub_key(self, seq):
        seq = seq.replace('-----BEGIN PQP PUBLIC KEY-----\n', '')
        seq = seq.replace('-----END PQP PUBLIC KEY-----\n', '')
        der = decoder.decode(base64.decodestring(seq), asn1Spec=ASN1PublicKey())[0]
        pub_key = PublicKey()
        pub_key.G = np.array(list(der['G']))
        pub_key.block_length = len(pub_key.G)
        return pub_key

    def get_der_pub_key(self, pub_key):
        template = '-----BEGIN PQP PUBLIC KEY-----\n{}-----END PQP PUBLIC KEY-----\n'
        der = ASN1PublicKey()
        der['G'] = self.to_bitstring(pub_key.G)
        data = base64.encodestring(encoder.encode(der))
        return template.format(data)

        
keygen = Keygen()
priv_key, pub_key = keygen.generate()

io = IO()
der_pub = io.get_der_pub_key(pub_key)
print der_pub
der = io.extract_der_pub_key(der_pub)

der_priv = io.get_der_priv_key(priv_key)
print der_priv
#der = io.extract_der_priv_key(der_priv)

