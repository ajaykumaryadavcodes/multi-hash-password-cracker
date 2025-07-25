import hashlib
import zlib
import binascii
import time
from Crypto.Hash import MD2, MD4, RIPEMD, SHA3_224, SHA3_256, SHA3_384, SHA3_512
from Crypto.Hash import SHA1, SHA224, SHA256, SHA384, SHA512

# Optional MD6 support
try:
    import md6
    HAS_MD6 = True
except ImportError:
    HAS_MD6 = False

# Special hash functions
def ntlm_hash(word):
    return hashlib.new('md4', word.encode('utf-16le')).hexdigest()

def crc16(word):
    crc = 0xFFFF
    for ch in word.encode():
        crc ^= ch << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return format(crc, '04x')

def crc32(word):
    return format(binascii.crc32(word.encode()) & 0xFFFFFFFF, '08x')

def adler32(word):
    return format(zlib.adler32(word.encode()) & 0xFFFFFFFF, '08x')

HASH_FUNCTIONS = {
    "MD2": lambda w: MD2.new(w.encode()).hexdigest(),
    "MD4": lambda w: MD4.new(w.encode()).hexdigest(),
    "MD5": lambda w: hashlib.md5(w.encode()).hexdigest(),
    "SHA1": lambda w: SHA1.new(w.encode()).hexdigest(),
    "SHA-224": lambda w: SHA224.new(w.encode()).hexdigest(),
    "SHA-256": lambda w: SHA256.new(w.encode()).hexdigest(),
    "SHA-384": lambda w: SHA384.new(w.encode()).hexdigest(),
    "SHA-512": lambda w: SHA512.new(w.encode()).hexdigest(),
    "SHA3-224": lambda w: SHA3_224.new(w.encode()).hexdigest(),
    "SHA3-256": lambda w: SHA3_256.new(w.encode()).hexdigest(),
    "SHA3-384": lambda w: SHA3_384.new(w.encode()).hexdigest(),
    "SHA3-512": lambda w: SHA3_512.new(w.encode()).hexdigest(),
    "RIPEMD-128": lambda w: RIPEMD.new(w.encode(), digest_bits=128).hexdigest(),
    "RIPEMD-160": lambda w: RIPEMD.new(w.encode(), digest_bits=160).hexdigest(),
    "RIPEMD-256": lambda w: RIPEMD.new(w.encode(), digest_bits=256).hexdigest(),
    "RIPEMD-320": lambda w: RIPEMD.new(w.encode(), digest_bits=320).hexdigest(),
    "NTLM": ntlm_hash,
    "CRC16": crc16,
    "CRC32": crc32,
    "Adler32": adler32
}

if HAS_MD6:
    HASH_FUNCTIONS["MD6-128"] = lambda w: md6.hash(w.encode(), 128).hex()
    HASH_FUNCTIONS["MD6-256"] = lambda w: md6.hash(w.encode(), 256).hex()
    HASH_FUNCTIONS["MD6-512"] = lambda w: md6.hash(w.encode(), 512).hex()

def crack_single(hash_input, hash_type, wordlist_file):
    print(f"\n[*] Cracking using hash type: {hash_type}")
    try:
        hash_func = HASH_FUNCTIONS[hash_type]
    except KeyError:
        print("[-] Unsupported hash type.")
        return

    with open(wordlist_file, 'r') as f:
        for word in f:
            word = word.strip()
            hashed = hash_func(word)
            if hashed.lower() == hash_input.lower():
                print(f"[+] Password found: {word}")
                return
    print("[-] Password not found.")

def crack_all(hash_input, wordlist_file):
    print("\n[*] Trying all supported hash types...\n")
    with open(wordlist_file, 'r') as f:
        words = [line.strip() for line in f]

    for hash_type, func in HASH_FUNCTIONS.items():
        print(f"[*] Trying with: {hash_type}")
        for word in words:
            try:
                hashed = func(word)
                if hashed.lower() == hash_input.lower():
                    print(f"[+] Password found: {word}")
                    print(f"[✓] Hash type: {hash_type}")
                    return
            except Exception as e:
                continue
    print("[-] Password not found in any hash type.")

if __name__ == "__main__":
    print("""
====================================
   🔐 Multi Hash Password Cracker
====================================
[1] Auto-detect hash type (try all)
[2] Select specific hash type
""")
    choice = input("Enter choice [1/2]: ").strip()

    hash_value = input("Enter the hash to crack: ").strip()
    wordlist_path = input("Enter path to wordlist (e.g., passwords.txt): ").strip()

    if choice == "1":
        crack_all(hash_value, wordlist_path)
    elif choice == "2":
        print("\nSupported hash types:")
        for h in HASH_FUNCTIONS:
            print(f" - {h}")
        hash_type = input("\nEnter hash type: ").strip().upper()
        crack_single(hash_value, hash_type, wordlist_path)
    else:
        print("[-] Invalid option.")
