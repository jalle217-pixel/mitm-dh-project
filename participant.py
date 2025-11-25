"""
Participant class representing a party (Alice or Bob).
It uses DiffieHellman for key agreement and XORCipher for message encryption/decryption.
"""

from .dh import DiffieHellman
from .cipher import XORCipher

class Participant:
    def __init__(self, name: str, dh_params: DiffieHellman, priv_bits: int = 32):
        self.name = name
        self.dh = dh_params
        self.priv = self.dh.generate_private_key(bits=priv_bits)
        self.pub = self.dh.generate_public_key(self.priv)
        self.shared_secret_int = None
        self.cipher = None

    def receive_their_public(self, their_pub: int):
        """Compute shared secret and create cipher with it."""
        self.shared_secret_int = self.dh.compute_shared(their_pub, self.priv)
        # create XOR cipher based on shared_secret_int
        self.cipher = XORCipher(self.shared_secret_int)

    def send_message(self, plaintext: bytes) -> bytes:
        if not self.cipher:
            raise ValueError("No shared key/cipher established")
        return self.cipher.encrypt(plaintext)

    def receive_message(self, ciphertext: bytes) -> bytes:
        if not self.cipher:
            raise ValueError("No shared key/cipher established")
        return self.cipher.decrypt(ciphertext)
