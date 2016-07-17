'''
This file is part of libPQP
Copyright (C) 2016 Carl Londahl <carl.londahl@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from pyasn1.codec.der import encoder, decoder

import pyasn1.type.univ
import pyasn1.type.namedtype as namedtype
import base64

from crypto.keygen import *
from crypto.private_key import *
from crypto.public_key import *

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

class ASN1Ciphertext(pyasn1.type.univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('C0',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('C1',    pyasn1.type.univ.BitString()),
        namedtype.NamedType('Sym',   pyasn1.type.univ.OctetString()),
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
        priv_key.block_length = len(priv_key.H_0)
        return priv_key

    def get_der_priv_key(self, priv_key):
        template = '-----BEGIN PQP PRIVATE KEY-----\n{}-----END PQP PRIVATE KEY-----\n'
        
        der = ASN1PrivateKey()
        der['H0'] = self.to_bitstring(priv_key.H_0)
        der['H1'] = self.to_bitstring(priv_key.H_1)
        der['H1inv'] = self.to_bitstring(priv_key.H_1inv)
        
        data = base64.encodestring(encoder.encode(der))
        return template.format(data)
        
    def extract_der_pub_key(self, seq):
        seq = seq.replace('-----BEGIN PQP PUBLIC KEY-----', '')
        seq = seq.replace('-----END PQP PUBLIC KEY-----', '')
        seq = seq.strip('\n')
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
    
    def get_der_ciphertext(self, c_0, c_1, symmetric_stream):
        template = '-----BEGIN PQP MESSAGE-----\n{}-----END PQP MESSAGE-----\n'
        der = ASN1Ciphertext()
        der['C0'] =  self.to_bitstring(c_0)
        der['C1'] =  self.to_bitstring(c_1)
        der['Sym'] =  symmetric_stream
        data = base64.encodestring(encoder.encode(der))
        return template.format(data)
    
    def extract_der_ciphertext(self, seq):
        seq = seq.replace('-----BEGIN PQP MESSAGE-----', '')
        seq = seq.replace('-----END PQP MESSAGE-----', '')
        seq = seq.strip('\n')
        der = decoder.decode(base64.decodestring(seq), asn1Spec=ASN1Ciphertext())[0]
        c_0 = np.array(list(der['C0']))
        c_1 = np.array(list(der['C1']))
        symmetric_stream = der['Sym'].asOctets()
        return c_0, c_1, symmetric_stream



#bask = IO()
#encoded = bask.get_der_ciphertext([1],[0], '\x00')
#print bask.extract_der_ciphertext(encoded)


