# Independent AES Crypt v0/v1/v2 writer used to create the legacy fixtures.
# Requires the `cryptography` package. Usage: legacy_writer.py VERSION PASSWORD IN OUT
import sys, os, hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def ackdf(pw, iv):
    d = iv + b"\0"*16
    for _ in range(8192): d = hashlib.sha256(d + pw).digest()
    return d
def cbc(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(); return e.update(data) + e.finalize()
version, password, src, dst = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
pt = open(src, "rb").read()
pw = password.encode("utf-16-le")
iv = os.urandom(16); key = ackdf(pw, iv)
rem = len(pt) % 16
padded = pt + bytes([16 - rem]) * (16 - rem) if rem else pt
if version == 0:
    ct = cbc(key, iv, padded)
    out = b"AES\x00" + bytes([rem]) + iv + ct + hmac.new(key, ct, hashlib.sha256).digest()
else:
    siv, skey = os.urandom(16), os.urandom(32)
    kb = cbc(key, iv, siv + skey)
    ct = cbc(skey, siv, padded)
    out = b"AES" + bytes([version, 0])
    if version == 2: out += b"\x00\x00"
    out += iv + kb + hmac.new(key, kb, hashlib.sha256).digest() + ct + bytes([rem]) + hmac.new(skey, ct, hashlib.sha256).digest()
open(dst, "wb").write(out)
