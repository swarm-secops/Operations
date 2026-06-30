import os
import statistics
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------- Parameters ----------------
KEY_SIZE = 32          # AES-256
MSG_SIZE = 32          # 32-byte message
ITERATIONS = 10000
WARMUP = 200

# ---------------- Test Data ----------------
key = AESGCM.generate_key(bit_length=256)
aes = AESGCM(key)

nonce = os.urandom(12)
plaintext = os.urandom(MSG_SIZE)
aad = None

# ---------------- Warm-up ----------------
for _ in range(WARMUP):
    ct = aes.encrypt(nonce, plaintext, aad)
    aes.decrypt(nonce, ct, aad)

# ---------------- Encryption Timing ----------------
enc_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    ciphertext = aes.encrypt(nonce, plaintext, aad)

    end = time.perf_counter_ns()

    enc_times.append(end - start)

# ---------------- Prepare Ciphertext ----------------
ciphertext = aes.encrypt(nonce, plaintext, aad)

# ---------------- Decryption Timing ----------------
dec_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    recovered = aes.decrypt(nonce, ciphertext, aad)

    end = time.perf_counter_ns()

    dec_times.append(end - start)

assert recovered == plaintext

# ---------------- Statistics ----------------
print("=" * 60)
print("AES-256-GCM Benchmark")
print("=" * 60)

print(f"Message Size      : {MSG_SIZE} bytes")
print(f"Iterations        : {ITERATIONS}")
print()

print("Encryption")
print(f"Average : {statistics.mean(enc_times):.2f} ns")
print(f"Median  : {statistics.median(enc_times):.2f} ns")
print(f"Minimum : {min(enc_times)} ns")
print(f"Maximum : {max(enc_times)} ns")

print()

print("Decryption")
print(f"Average : {statistics.mean(dec_times):.2f} ns")
print(f"Median  : {statistics.median(dec_times):.2f} ns")
print(f"Minimum : {min(dec_times)} ns")
print(f"Maximum : {max(dec_times)} ns")

print()

print(f"Encryption Avg : {statistics.mean(enc_times)/1000:.3f} µs")
print(f"Decryption Avg : {statistics.mean(dec_times)/1000:.3f} µs")