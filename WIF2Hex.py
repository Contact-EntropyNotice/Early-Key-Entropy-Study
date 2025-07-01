"""
wif2hex.py – Convert a raw 32-byte Bitcoin private key to
its WIF representation, derive the corresponding public key,
and generate the matching P2PKH address.
Usage example (see __main__): python wif2hex.py
"""
import hashlib
import base58
from ecdsa import SigningKey, SECP256k1
# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def sha256(data: bytes) -> bytes:
"""Return SHA-256 digest of *data*."""
return hashlib.sha256(data).digest()
def ripemd160(data: bytes) -> bytes:
"""Return RIPEMD-160 digest of *data*."""
h = hashlib.new("ripemd160")
h.update(data)
return h.digest()
def base58check(prefix: bytes, payload: bytes) -> str:
"""
Encode *prefix + payload* using Base58Check:
- double-SHA256 checksum (4 bytes) appended,
- Base58 alphabet encoding.
"""
data = prefix + payload
checksum = sha256(sha256(data))[:4]
return base58.b58encode(data + checksum).decode()
# ---------------------------------------------------------------------------
# Core routine
# ---------------------------------------------------------------------------
def generate_bitcoin_info(priv_hex: str, compressed: bool = False) -> dict:
"""
Given a 64-hex-char private key, return a dict with:
• raw bytes, WIF, public key, address (P2PKH),
• whether the key is compressed.
"""
# 1. Private key, 32 bytes
priv_bytes = bytes.fromhex(priv_hex)
if len(priv_bytes) != 32:
raise ValueError("Invalid private key: must be 32 bytes")
# 2. Derive public key via ECDSA secp256k1
sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
vk = sk.get_verifying_key()
if compressed:
pubkey = (b"\x02" if vk.pubkey.point.y() % 2 == 0 else b"\x03") + \
vk.pubkey.point.x().to_bytes(32, "big")
else:
pubkey = b"\x04" + vk.to_string()
# 3. Bitcoin address (P2PKH, mainnet prefix 0x00)
pubkey_hash = ripemd160(sha256(pubkey))
address = base58check(b"\x00", pubkey_hash)
# 4. WIF (Wallet Import Format, mainnet prefix 0x80)
wif_payload = priv_bytes + (b"\x01" if compressed else b"")
wif = base58check(b"\x80", wif_payload)
return {
"private_hex": priv_hex,
"private_bytes": priv_bytes.hex(),
"wif": wif,
"pubkey": pubkey.hex(),
"compressed": compressed,
"address": address,
}
# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
secret_hex = "37418f34b941fbc7dee0e89b6bb9d5868e164287f33f1bf5db9173304c0bc1ac"
print("=== Uncompressed ===")
info = generate_bitcoin_info(secret_hex, compressed=False)
for k, v in info.items():
print(f"{k}: {v}")
print("\n=== Compressed ===")
info_c = generate_bitcoin_info(secret_hex, compressed=True)
for k, v in info_c.items():
print(f"{k}: {v}")
