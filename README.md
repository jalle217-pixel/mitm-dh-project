# MITM Attack on Diffie–Hellman Key Exchange — Course Project

## Project Title
Man-in-the-Middle (MITM) Attack on Diffie–Hellman Key Exchange — Educational Implementation

## Overview
This project implements Diffie–Hellman (DH) key exchange from first principles in Python and demonstrates a man-in-the-middle (MITM) attack that intercepts and substitutes public keys. The attacker (Mallory) establishes independent shared secrets with both legitimate parties (Alice and Bob), enabling Mallory to decrypt, read, and modify messages exchanged between them.

> **Important:** This is an educational implementation to demonstrate protocol weaknesses when authentication is not used. It is **not secure** and should never be used in production.

## Project Structure
mitm-dh-project/
├─ .gitignore
├─ README.md
├─ demo.py
├─ dh/
│ ├─ init.py
│ ├─ dh.py
│ ├─ cipher.py
│ ├─ participant.py
│ └─ mitm.py


- `dh/dh.py` — Diffie–Hellman math: key generation, public key, shared secret.
- `dh/cipher.py` — Simple XOR stream cipher using PRNG derived from shared int (educational).
- `dh/participant.py` — Participant class (Alice/Bob): manages keys and message encryption/decryption.
- `dh/mitm.py` — Man-in-the-middle attacker class (Mallory).
- `demo.py` — Script that runs two scenarios: normal exchange and MITM attack.

## Approach
1. Implement DH parameter handling (p, g), private key generation, public key calculation, and shared secret computation using modular exponentiation.
2. Build a tiny stream cipher that derives a keystream from the shared integer secret so that two parties with the same shared secret can communicate by XOR encryption/decryption.
3. Implement a `Mitm` class that intercepts public keys and substitutes its own public key, leading to the attacker sharing secrets with both endpoints.
4. Demonstrate with `demo.py`:
   - Scenario A: normal DH exchange (no attacker) — Alice and Bob share the same secret.
   - Scenario B: MITM — Mallory intercepts and reads/modifies messages.

## How to Run
1. Clone the repository (or create files locally as provided).
2. From the repo root run:

```bash
python demo.py