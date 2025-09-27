#!/usr/bin/env python3
"""
file_crypto.py

Encrypts and decrypts files (images or any binary) using AES-256-CBC or 3DES.
Usage:
    python file_crypto.py encrypt  input.jpg output.enc --password "mypassword" --algo AES
    python file_crypto.py decrypt  output.enc decrypted.jpg --password "mypassword" --algo AES
"""

import argparse
import struct
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# Constants for file header format
MAGIC = b'FC01'     # 4 bytes magic/version
SALT_SIZE = 16      # PBKDF2 salt bytes
PBKDF2_ITER = 200_000

# Supported algorithms
ALGOS = ('AES', '3DES')

# PKCS7 padding helpers
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise ValueError("Invalid padding (empty data)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def derive_key(password: str, salt: bytes, algo: str):
    password_bytes = password.encode('utf-8')
    if algo == 'AES':
        # AES-256 -> 32 bytes
        return PBKDF2(password_bytes, salt, dkLen=32, count=PBKDF2_ITER, hmac_hash_module=None)
    elif algo == '3DES':
        # 3DES uses 24-byte key
        return PBKDF2(password_bytes, salt, dkLen=24, count=PBKDF2_ITER, hmac_hash_module=None)
    else:
        raise ValueError("Unsupported algorithm")

def encrypt_file(in_path: str, out_path: str, password: str, algo: str = 'AES'):
    if algo not in ALGOS:
        raise ValueError(f"Unsupported algorithm: {algo}")

    # read file bytes
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt, algo)

    if algo == 'AES':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block_size = 16
    else:  # 3DES
        iv = get_random_bytes(8)
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        block_size = 8

    padded = pkcs7_pad(plaintext, block_size)
    ciphertext = cipher.encrypt(padded)

    # Write header: MAGIC (4) | algo (4) | salt_len(1) | salt | iv_len(1) | iv | ciphertext
    # Use fixed-size fields for algo for simplicity
    algo_field = algo.encode('ascii').ljust(4, b'\x00')
    with open(out_path, 'wb') as f:
        f.write(MAGIC)
        f.write(algo_field)
        f.write(struct.pack('B', SALT_SIZE))
        f.write(salt)
        f.write(struct.pack('B', len(iv)))
        f.write(iv)
        f.write(ciphertext)

    print(f"Encrypted {in_path} -> {out_path} using {algo}. Salt and IV stored in file header.")

def decrypt_file(in_path: str, out_path: str, password: str):
    with open(in_path, 'rb') as f:
        # read header
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("File magic/version mismatch or not an encrypted file produced by this tool.")
        algo_field = f.read(4).rstrip(b'\x00')
        algo = algo_field.decode('ascii')
        salt_len = struct.unpack('B', f.read(1))[0]
        salt = f.read(salt_len)
        iv_len = struct.unpack('B', f.read(1))[0]
        iv = f.read(iv_len)
        ciphertext = f.read()

    if algo not in ALGOS:
        raise ValueError(f"Unsupported algorithm in file header: {algo}")

    key = derive_key(password, salt, algo)

    if algo == 'AES':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block_size = 16
    else:  # 3DES
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        block_size = 8

    padded = cipher.decrypt(ciphertext)
    try:
        plaintext = pkcs7_unpad(padded)
    except ValueError as e:
        raise ValueError("Decryption failed (bad password or corrupted data).") from e

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted {in_path} -> {out_path} using {algo}.")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using AES-256-CBC or 3DES.")
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_enc = sub.add_parser('encrypt', help='Encrypt a file')
    p_enc.add_argument('input', help='Input file path')
    p_enc.add_argument('output', help='Output file path')
    p_enc.add_argument('--password', '-p', required=True, help='Password')
    p_enc.add_argument('--algo', '-a', choices=ALGOS, default='AES', help='Algorithm (default AES)')

    p_dec = sub.add_parser('decrypt', help='Decrypt a file')
    p_dec.add_argument('input', help='Input file path (encrypted)')
    p_dec.add_argument('output', help='Output file path (decrypted)')
    p_dec.add_argument('--password', '-p', required=True, help='Password')

    args = parser.parse_args()

    if args.cmd == 'encrypt':
        encrypt_file(args.input, args.output, args.password, algo=args.algo)
    elif args.cmd == 'decrypt':
        decrypt_file(args.input, args.output, args.password)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
