# Independent, deterministic AES Crypt writer (versions 0-3) used to create
# kat.txt. Requires the `cryptography` package.
import hashlib, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def ackdf(pw, iv):
    d = iv + b"\0" * 16
    for _ in range(8192):
        d = hashlib.sha256(d + pw).digest()
    return d

def cbc(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()

def write(version, pw, iterations, public_iv, session_iv, session_key, pt, extensions=()):
    if version == 3:
        key = hashlib.pbkdf2_hmac("sha512", pw, public_iv, iterations, 32)
        n = 16 - len(pt) % 16
        body, rem = pt + bytes([n]) * n, 0
    else:
        key = ackdf(pw, public_iv)
        rem = len(pt) % 16
        body = pt + bytes([16 - rem]) * (16 - rem) if rem else pt
    out = b"AES" + bytes([version, rem if version == 0 else 0])
    if version >= 2:
        for ext in extensions:
            out += len(ext).to_bytes(2, "big") + ext
        out += b"\0\0"
    if version == 3:
        out += iterations.to_bytes(4, "big")
    out += public_iv
    if version == 0:
        ct = cbc(key, public_iv, body)
        return out + ct + hmac.new(key, ct, hashlib.sha256).digest()
    kb = cbc(key, public_iv, session_iv + session_key)
    out += kb + hmac.new(key, kb + (b"\x03" if version == 3 else b""), hashlib.sha256).digest()
    ct = cbc(session_key, session_iv, body)
    if version in (1, 2):
        ct_trailer = bytes([rem])
    else:
        ct_trailer = b""
    return out + ct + ct_trailer + hmac.new(session_key, ct, hashlib.sha256).digest()

if __name__ == "__main__":
    text = "kat password ✓"
    public_iv, session_iv = bytes(range(16)), bytes(range(16, 32))
    session_key = bytes(range(32, 64))
    ext = b"CREATED_BY\0kat_writer.py"
    print("# Streams from kat_writer.py. `password` is the text \"kat password ✓\"")
    print("# encoded as each version expects (UTF-16LE for 0-2, UTF-8 for 3).\n")
    for version in range(4):
        for pt in (b"", b"Hello, AES Crypt!", bytes(range(48))):
            pw = text.encode("utf-8" if version == 3 else "utf-16-le")
            exts = (ext,) if version >= 2 else ()
            stream = write(version, pw, 1000, public_iv, session_iv, session_key, pt, exts)
            print(f"version = {version:02x}\npassword = {pw.hex()}\niterations = {1000:08x}\npublic_iv = {public_iv.hex()}"
                  f"\nsession_iv = {session_iv.hex()}\nsession_key = {session_key.hex()}\nextension = {(ext if version >= 2 else b'').hex()}"
                  f"\nplaintext = {pt.hex()}\nstream = {stream.hex()}\n")
