"""
Mitm class simulates an attacker that intercepts public keys and substitutes its own,
resulting in attacker sharing separate secrets with both parties.

Example flow simulated here:
- Alice sends A = g^a mod p -> attacker intercepts, sends M = g^m to Bob
- Bob sends B = g^b mod p -> attacker intercepts, sends M' = g^m' to Alice
Attacker then holds secret1 = (A)^m (shared with Alice) and secret2 = (B)^m' (shared with Bob)
For the simplest demonstration we'll use a single attacker private key m and substitute its public key both ways.
"""

from .dh import DiffieHellman
from .participant import Participant
from .cipher import XORCipher

class Mitm:
    def __init__(self, dh_params: DiffieHellman, name: str = "Mallory", priv_bits: int = 32):
        self.name = name
        self.dh = dh_params
        self.priv = self.dh.generate_private_key(bits=priv_bits)
        self.pub = self.dh.generate_public_key(self.priv)
        # will store two shared secrets (one with Alice, one with Bob)
        self.shared_with_alice = None
        self.shared_with_bob = None
        self.cipher_alice = None
        self.cipher_bob = None

    def intercept_alice_to_bob(self, alice_pub: int):
        """
        Called when Alice's public is sent to Bob: attacker intercepts and
        sends attacker's public to Bob instead.
        Returns: value attacker forwards to Bob (attacker's pub)
        """
        # compute shared secret with Alice's pub
        self.shared_with_alice = pow(alice_pub, self.priv, self.dh.p)
        self.cipher_alice = XORCipher(self.shared_with_alice)
        # attacker sends its own public to Bob
        return self.pub

    def intercept_bob_to_alice(self, bob_pub: int):
        """
        Called when Bob's public is sent to Alice: attacker intercepts and
        sends attacker's public to Alice instead.
        """
        self.shared_with_bob = pow(bob_pub, self.priv, self.dh.p)
        self.cipher_bob = XORCipher(self.shared_with_bob)
        return self.pub

    def read_alice_message(self, ciphertext: bytes) -> bytes:
        """Decrypt message from Alice using the secret with Alice."""
        if not self.cipher_alice:
            raise ValueError("No cipher with Alice")
        return self.cipher_alice.decrypt(ciphertext)

    def forward_to_bob(self, plaintext: bytes) -> bytes:
        """Encrypt plaintext using cipher shared with Bob so Bob will accept it as from attacker (or Alice)."""
        if not self.cipher_bob:
            raise ValueError("No cipher with Bob")
        return self.cipher_bob.encrypt(plaintext)

    def read_bob_message(self, ciphertext: bytes) -> bytes:
        if not self.cipher_bob:
            raise ValueError("No cipher with Bob")
        return self.cipher_bob.decrypt(ciphertext)

    def forward_to_alice(self, plaintext: bytes) -> bytes:
        if not self.cipher_alice:
            raise ValueError("No cipher with Alice")
        return self.cipher_alice.encrypt(plaintext)
