# multi-hash-password-cracker
A Python tool to crack multiple hash types using a wordlist.
# 🔐 Multi Hash Password Cracker

A Python-based hash cracker that supports cracking multiple hash types using a dictionary (wordlist) attack.

## 💡 Features

- Crack hashes like:
  - MD2, MD4, MD5, NTLM
  - SHA1, SHA-224, SHA-256, SHA-384, SHA-512
  - SHA3-224, SHA3-256, SHA3-384, SHA3-512
  - RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320
  - CRC16, CRC32, Adler32
- Two cracking modes:
  - 🔍 Auto-detect hash type
  - 🎯 Manual hash type selection
- Simple CLI interface

## 🛠️ Requirements

- Python 3.x
- pycryptodome

Install with:

```bash
pip install -r requirements.txt

