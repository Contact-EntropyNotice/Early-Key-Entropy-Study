"""
final_rand_bytes2.py – Reconstruct the 32-byte output produced by
OpenSSL 0.9.8h’s `ssleay_rand_bytes()` after four SHA-1 rounds.
The script takes:
• the first four 20-byte fragments of the global RNG state
(`initial_states`), extracted from instrumentation logs;
• the four corresponding 20-byte SHA-1 digests
(`output_digests`) returned by `ssleay_rand_bytes()`.
It mimics the internal loop that:
1. XORs each digest back into the state[] array, and
2. appends the ten most significant bytes of each digest
to the caller’s output buffer, until 32 bytes are filled.
Running the script should print exactly the deterministic
32-byte sequence reproduced in the lab:
37 41 8F 34 B9 41 FB C7 DE E0
E8 9B 6B B9 D5 86 8E 16 42 87
F3 3F 1B F5 DB 91 73 30 4C 0B C1 AC
"""

import hashlib 
# --- Inputs captured from ssleay_rand_bytes instrumentation ---
initial_states = [
bytes.fromhex("9CBB44A0E9C5E9289145"),
bytes.fromhex("47D7606CF8A8B8C4A1B2"),
bytes.fromhex("4F93520EAC0D7A575BF8"),
bytes.fromhex("D9143FBD79CCEF0C1F40"),
]
output_digests = [
bytes.fromhex("417B0FA0B141CC4DD22537418F34B941FBC7DEE0"),
bytes.fromhex("F4280EBD01A57B3751EFE89B6BB9D5868E164287"),
bytes.fromhex("7153EF212DDE669B5FB9F33F1BF5DB9173304C0B"),
bytes.fromhex("593BBC4CB4494E265054C1AC5ACFB155F627C5B7"),
]

buf = bytearray(b"\xCD" * 32)
# Mutable copy of the first state fragment
state = bytearray(initial_states[0])
# Final 32-byte output buffer
result_bytes = bytearray()
# --- Emulate the four SHA-1 iterations ---
for i in range(4):
digest = output_digests[i]
print(f"\n=== Iteration {i} ===")
print(f"D{i} = {digest.hex().upper()}")
# XOR each byte of the digest into the current state fragment
for j in range(len(state)):
xor_before = state[j]
xor_after = xor_before ^ digest[j]
state[j] = xor_after
print(f"state_xor_{j}: {xor_before:02X}{xor_after:02X}")
# Append the ten most significant bytes of the digest
upper = digest[10:20]
for k, byte in enumerate(upper):
if len(result_bytes) < 32:
result_bytes.append(byte)
print(f"output_byte_{k}: {byte:02X}")
# Load the next state fragment if any
if i + 1 < len(initial_states):
state = bytearray(initial_states[i + 1])
# --- Display the reconstructed 32-byte random output ---
print("\nOutput random bytes (32 bytes):")
print(" ".join(f'{b:02X}' for b in result_bytes))
