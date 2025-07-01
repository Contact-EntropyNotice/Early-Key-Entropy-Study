"""
sha1test.py – Minimal script to reproduce the first SHA-1 digest
computed inside OpenSSL 0.9.8h’s `ssleay_rand()` fallback path.
The script mirrors the very first call to SHA-1 when:
• `local_md` and the first 20 bytes of the global `state[]`
are still zero;
• the entropy pool has been seeded only with the constant
20-byte buffer taken from the memory image (`buf`);
• `md_count` (`md_c`) is two little-endian 32-bit integers,
both equal to 0.
Running `python sha1test.py` should print:
SHA1 Digest (hex): 50247E600D2CC55E558E3353EB54C6C90D17EE98
"""

import hashlib
# --- Parameters extracted from the controlled environment ---
# 1. Initial value of local_md (20 bytes of 0x00 for iteration 0)
local_md = bytes.fromhex("00" * 20)
# 2. Initial value of state[0:20] (also 20 bytes of 0x00)
state_fragment = bytes.fromhex("00" * 20)
# 3. Buffer used as “buf” (20-byte seed taken from the memory snapshot)
buf = bytes.fromhex("6856EB225FCEDB010000000000000000DB000000")
# 4. md_c (md_count): two little-endian 32-bit integers, both zero
md_c = (0).to_bytes(4, "little") + (0).to_bytes(4, "little") # 8 bytes
# --- SHA-1 computation identical to OpenSSL’s first round ---
sha1 = hashlib.sha1()
sha1.update(local_md)
sha1.update(state_fragment)
sha1.update(buf)
sha1.update(md_c)
digest = sha1.digest()
print("SHA1 Digest (hex):", digest.hex().upper())
