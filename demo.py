"""
It simulates a client (Alice) and server (Bob) performing DH key exchange
and sending messages. It shows:
- Normal (no attacker): Alice and Bob share the same secret and can communicate.
- MITM: Mallory intercepts public keys and reads/modifies messages.

Usage:
    python demo.py
"""

from dh.dh import DiffieHellman
from dh.participant import Participant
from dh.mitm import Mitm

def scenario_no_mitm():
    print("=== Scenario: No MITM ===")
    dh = DiffieHellman()
    alice = Participant("Alice", dh)
    bob = Participant("Bob", dh)

    # Exchange public keys directly
    alice.receive_their_public(bob.pub)
    bob.receive_their_public(alice.pub)

    # Check they derived same shared secret (int) via their cipher state
    print("Alice shared:", alice.shared_secret_int)
    print("Bob shared:  ", bob.shared_secret_int)
    assert alice.shared_secret_int == bob.shared_secret_int, "Shared secrets differ!"

    # Send a message
    plaintext = b"Hello Bob, this is Alice."
    ct = alice.send_message(plaintext)
    pt = bob.receive_message(ct)
    print("Bob received:", pt)

def scenario_with_mitm():
    print("\n=== Scenario: With MITM ===")
    dh = DiffieHellman()
    alice = Participant("Alice", dh)
    bob = Participant("Bob", dh)
    mallory = Mitm(dh)

    # Alice -> Bob (intercepted)
    forwarded_to_bob = mallory.intercept_alice_to_bob(alice.pub)
    # Bob receives attacker's pub thinking it's Alice's
    bob.receive_their_public(forwarded_to_bob)

    # Bob -> Alice (intercepted)
    forwarded_to_alice = mallory.intercept_bob_to_alice(bob.pub)
    # Alice receives attacker's pub thinking it's Bob's
    alice.receive_their_public(forwarded_to_alice)

    # Now Mallory has separate shared secrets with Alice and Bob
    print("Mallory shared w/ Alice:", mallory.shared_with_alice)
    print("Mallory shared w/ Bob:  ", mallory.shared_with_bob)
    print("Alice thinks shared:", alice.shared_secret_int)
    print("Bob thinks shared:  ", bob.shared_secret_int)

    # Alice sends message (Mallory intercepts)
    plaintext = b"Hi Bob, it is Alice (confidential)."
    ct_alice = alice.send_message(plaintext)
    # Mallory reads it:
    read_by_mallory = mallory.read_alice_message(ct_alice)
    print("Mallory read Alice->Bob:", read_by_mallory)

    # Mallory may modify then forward to Bob
    modified = read_by_mallory.replace(b"confidential", b"NOT SECRET   ")
    ct_to_bob = mallory.forward_to_bob(modified)
    received_by_bob = bob.receive_message(ct_to_bob)
    print("Bob actually received:", received_by_bob)

    # Bob replies
    reply = b"Hello Alice (from Bob)."
    ct_bob = bob.send_message(reply)
    read_by_mallory = mallory.read_bob_message(ct_bob)
    print("Mallory read Bob->Alice:", read_by_mallory)
    # Mallory forwards to Alice
    ct_to_alice = mallory.forward_to_alice(read_by_mallory)
    received_by_alice = alice.receive_message(ct_to_alice)
    print("Alice actually received:", received_by_alice)

if __name__ == "__main__":
    scenario_no_mitm()
    scenario_with_mitm()

