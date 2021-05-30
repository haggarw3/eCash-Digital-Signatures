#!/usr/bin/env python
# coding:utf-8
"""
  Purpose:  Lamport One-Time Signature Scheme (LOTSS) implementation.
  Created:  20/04/2017
  Code Courtesy: Jonas1312
  Last Modified
"""

from bitstring import BitArray
# make dealing with binary data in Python as easy as possible
import hashlib
# to generate hash function of any data
from os import urandom
# os.urandom() method is used to generate a string of size random bytes
# suitable for cryptographic use

class LamportSignature:
    """Lamport signature class.


    Attributes:
        private_key (list): Private key.
        public_key (list): Public key.
        used (boolean): Keys already used to sign a message.

    """

    def __init__(self):
        """ LamportSignature object constructor"""
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()
        self.used = False

    @staticmethod
    def generate_private_key():
        """Generate a private key.
            Also called Secret Key

        Returns:
            (list): Private key, 2×256×256 bits = 16 KiB.

            How ?? See below :
            32 bytes = 256 bits
            bytearrray returns a byte array object - it is an array of bytes

            We have 2 rows of 256 blocks
            Each block has a random byte array of 32 bytes or 256 bits
        """
        return [(bytearray(urandom(32)), bytearray(urandom(32))) for i in range(256)]

    def generate_public_key(self):
        """Generate a public key.

        Returns:
            (list): Public key, 2×256×256 bits = 16 KiB.

            The structure is same as the primary key / Secret Key
            Except that it stores hashes of all the random bytes

            This key is known to other people, can be shared

            hash function has been defined below
            It uses the hashlib library
        """
        return [(self.hash(a), self.hash(b)) for (a, b) in self.private_key]


    def get_key(self, key_type):
        """Getter for the public or private key.

        Args:
            key_type (str): 'public' or 'private'.

        Returns:
            (bytearray/list): Public key.

        """
        if key_type == 'public':
            key = self.public_key
        else:
            key = self.private_key
        return key


    def sign(self, msg):
        """Sign a message with the Lamport signature.

        Args:
            msg (str): Message to sign.

        Returns:
            (list): Signature of the message, sequence of 256 random numbers, 256×256 bits.

        """
        if self.used:
            raise ValueError("Private and public keys already used!")
        self.used = True
        msg_hash = self.hash(msg)
        signature = []
        for (a, b), bit in zip(self.private_key, BitArray(bytes=msg_hash).bin):
            if bit == "0":
                signature.append(a)
            elif bit == "1":
                signature.append(b)
        return signature

    @classmethod
    def verify(cls, msg, signature, public_key):
        """Verify signature of the message.

        Args:
            msg (str): Message to check.
            signature (list): Signature of the message, sequence of 256 random numbers, 256×256 bits.
            public_key (list): Public key, 2×256×256 bits.

        Returns:
            (boolean): True if signature of the message is right otherwise False.

        """
        msg_hash = cls.hash(msg)
        signature_hash = [cls.hash(i) for i in signature]
        for sig_hash, (a, b), bit in zip(signature_hash, public_key, BitArray(bytes=msg_hash).bin):
            if (bit == "0" and sig_hash != a) or (bit == "1" and sig_hash != b):
                return False
        return True

    @staticmethod
    def hash(data):
        """Calculate sha256 hash of 'data'.

        Args:
            (str/bytearray): Data to hash.
        Returns:
            (bytearray): bytes of the hash.
        """
        if type(data) is not bytearray:
            data = data.encode('utf-8')
        return bytearray(hashlib.sha256(data).digest())


def main():
    for msg_sent, msg_to_check in (("abc", "abc"), ("abc", "aaa"), ("abc", "aabc")):
        lamport = LamportSignature()
        signature = lamport.sign(msg_sent)
        print(msg_sent, msg_to_check, LamportSignature.verify(msg_to_check, signature, lamport.public_key))


if __name__ == "__main__":
    main()