# StegArmor :: Encrypted Image Steganography Tool

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)
![Security](https://img.shields.io/badge/cipher-AES--256--GCM-green?logo=letsencrypt&logoColor=white)
![KDF](https://img.shields.io/badge/KDF-PBKDF2--HMAC--SHA256-orange)
![License](https://img.shields.io/badge/license-MIT-brightgreen)

> **StegArmor** is a defense-in-depth security utility engineered in Python 3. It combines **AES-256-GCM authenticated encryption** with **Least Significant Bit (LSB) image steganography** to facilitate covert payload embedding inside lossless PNG carrier images.

---

## Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Cryptographic Specification](#cryptographic-specification)
- [Installation & Setup](#installation--setup)
- [Usage Guide](#usage-guide)
  - [Command-Line Interface (CLI)](#1-command-line-interface-cli)
  - [Graphical User Interface (GUI)](#2-graphical-user-interface-gui)
- [License](#license)

---

## Overview

StegArmor provides a layered privacy model. Hiding raw plaintext via steganography leaves data exposed to steganalysis extraction. Conversely, standard encrypted payloads attract suspicion during network transit. StegArmor resolves both vulnerabilities by encrypting payloads prior to LSB pixel distribution, ensuring both **obscurity** and **cryptographic confidentiality**.

---

## Key Features

* **[+] AES-256-GCM Authenticated Encryption:** Secures payloads with Galois/Counter Mode, guaranteeing confidentiality and tamper resistance.
* **[+] Hardened Key Derivation:** Implements PBKDF2-HMAC-SHA256 utilizing 390,000 hashing iterations and random per-execution salts.
* **[+] LSB Image Manipulation:** Modifies least significant bits across pixel R, G, and B channels without causing perceptible visual artifacting.
* **[+] Dual Operation Modes:** Offers full scriptability via a CLI engine (`stegarmor.py`) alongside an intuitive desktop GUI (`stegarmor_gui.py`).
* **[+] Pre-Flight Capacity Verification:** Calculates carrier image storage capabilities prior to execution to prevent payload truncation.
* **[!] Graceful Error Handling:** Explicitly traps incorrect passphrases, missing header markers, and corrupted carrier files.

---

## Cryptographic Specification

| Technical Layer | Implementation Standard |
| :--- | :--- |
| **Symmetric Cipher** | AES-256 in Galois/Counter Mode (GCM) |
| **Integrity Check** | 128-bit Authentication Tag (AEAD) |
| **Key Derivation Function** | PBKDF2-HMAC-SHA256 |
| **KDF Iterations** | 390,000 rounds |
| **Initialization Vectors** | 16-byte random salt, 12-byte random IV per message |
| **Carrier Compatibility** | Lossless PNG (RGB / RGBA modes) |

---

## Installation & Setup

### Requirements
* Python 3.10+
* Pillow
* Cryptography

### Environment Setup
```bash
# Clone the repository
git clone [https://github.com/Nabihhaaa/StegArmor.git](https://github.com/Nabihhaaa/StegArmor.git)
cd StegArmor

# Initialize virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

Usage Guide
1. Command-Line Interface (CLI)
Embed Payload:

Bash
python3 stegarmor.py embed -i input.png -o stego_output.png -m "CONFIDENTIAL DATA" -p 'SecurePassphrase123!'
Extract Payload:

Bash
python3 stegarmor.py extract -i stego_output.png -p 'SecurePassphrase123!'
Check Carrier Capacity:

Bash
python3 stegarmor.py capacity -i input.png
2. Graphical User Interface (GUI)
Launch the native desktop interface:

Bash
python3 stegarmor_gui.py


