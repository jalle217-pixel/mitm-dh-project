"""
Very simple XOR stream cipher for demonstration.

- Derives a keystream from the shared secret integer by repeatedly hashing / transforming the integer
  via simple math to produce bytes. (We avoid using hashlib to be conservative per instructions.)
- NOT cryptographically secure. Only for demonstration to show that attacker who has shared secret can read messages.
"""

from typing import ByteString

def int_to_bytes(n: int) -> bytes:
    """Convert integer to bytes (big endian)."""
    if n == 0:
        return b"\x00"
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(out))

class XORCipher:
    def __init__(self, shared_secret_int: int):
        self.secret = shared_secret_int
        # initialize a simple PRNG state derived from secret
        self._state = shared_secret_int & 0xFFFFFFFFFFFFFFFF

    def _next_byte(self) -> int:
        """Produce a pseudo-random byte from internal state. LCG-like (not secure)."""
        # constants from minimal LCG (educational)
        a = 6364136223846793005
        c = 1
        self._state = (a * self._state + c) & 0xFFFFFFFFFFFFFFFF
        return self._state & 0xFF

    def keystream(self, n: int) -> bytes:
        return bytes(self._next_byte() for _ in range(n))

    def encrypt(self, plaintext: ByteString) -> bytes:
        ks = self.keystream(len(plaintext))
        return bytes([p ^ k for p, k in zip(plaintext, ks)])

    def decrypt(self, ciphertext: ByteString) -> bytes:
        # XOR is symmetric
        return self.encrypt(ciphertext)
