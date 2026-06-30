import os
import time
import statistics

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ---------------- Parameters ----------------
ITERATIONS = 1000
WARMUP = 50

message = os.urandom(32)

# -------------------------------------------------------
# Warm-up
# -------------------------------------------------------
for _ in range(WARMUP):

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

# -------------------------------------------------------
# Key Generation Benchmark
# -------------------------------------------------------

key_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    end = time.perf_counter_ns()

    key_times.append(end - start)

# -------------------------------------------------------
# Signing Benchmark
# -------------------------------------------------------

private_key = ec.generate_private_key(ec.SECP256R1())

sign_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )

    end = time.perf_counter_ns()

    sign_times.append(end - start)

# -------------------------------------------------------
# Verification Benchmark
# -------------------------------------------------------

public_key = private_key.public_key()

signature = private_key.sign(
    message,
    ec.ECDSA(hashes.SHA256())
)

verify_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    public_key.verify(
        signature,
        message,
        ec.ECDSA(hashes.SHA256())
    )

    end = time.perf_counter_ns()

    verify_times.append(end - start)

# -------------------------------------------------------
# Results
# -------------------------------------------------------

print("=" * 60)
print("ECDSA Benchmark")
print("=" * 60)

print("Curve          : NIST P-256 (secp256r1)")
print("Hash           : SHA-256")
print(f"Iterations     : {ITERATIONS}")
print()

print("Key Generation")
print(f"Average : {statistics.mean(key_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(key_times)/1e6:.3f} ms")
print(f"Minimum : {min(key_times)/1e6:.3f} ms")
print(f"Maximum : {max(key_times)/1e6:.3f} ms")

print()

print("Signature Generation")
print(f"Average : {statistics.mean(sign_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(sign_times)/1e6:.3f} ms")
print(f"Minimum : {min(sign_times)/1e6:.3f} ms")
print(f"Maximum : {max(sign_times)/1e6:.3f} ms")

print()

print("Signature Verification")
print(f"Average : {statistics.mean(verify_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(verify_times)/1e6:.3f} ms")
print(f"Minimum : {min(verify_times)/1e6:.3f} ms")
print(f"Maximum : {max(verify_times)/1e6:.3f} ms")