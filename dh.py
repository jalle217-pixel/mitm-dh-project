"""
Diffie-Hellman utilities.

Implements:
- DiffieHellman class that holds (p, g) parameters
- safe modular exponentiation uses Python pow(base, exp, mod)
- small helper to pick a private key in a given range

This is educational — use small primes for demonstration. For slightly bigger demo primes you can
replace the default p/g with recommended RFC primes (not included here to keep file short).
"""

import random

class DiffieHellman:
    def __init__(self, p: int = None, g: int = None):
        """
        p: prime modulus
        g: generator
        If not provided, we use small demo-safe defaults (not secure).
        """
        # Demo parameters (very small; insecure). Replace p,g for stronger demo.
        self.p = p or 0xFFFFFFFB  # large-ish 32-bit prime (for demo)
        self.g = g or 5

    def generate_private_key(self, bits: int = 32):
        """Generate a random private key (integer). For demo, keep bits small so output is readable."""
        if bits < 8:
            bits = 8
        # use random.getrandbits (built-in) to create private integer
        priv = random.getrandbits(bits)
        # make sure 1 <= priv < p
        priv = max(2, priv % (self.p - 2))
        return priv

    def generate_public_key(self, private_key: int):
        """Compute public key g^a mod p"""
        return pow(self.g, private_key, self.p)

    def compute_shared(self, their_pub: int, private_key: int):
        """Compute shared secret (their_pub ^ private_key mod p)"""
        return pow(their_pub, private_key, self.p)
