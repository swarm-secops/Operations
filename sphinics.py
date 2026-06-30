import oqs
import os
import time
import statistics

# -----------------------------------------------------
# Parameters
# -----------------------------------------------------

ALGORITHM = "SLH_DSA_PURE_SHAKE_128F"

ITERATIONS = 1000
WARMUP = 50

MESSAGE = os.urandom(32)

# -----------------------------------------------------
# Warm-up
# -----------------------------------------------------

for _ in range(WARMUP):

    signer = oqs.Signature(ALGORITHM)

    public_key = signer.generate_keypair()

    signature = signer.sign(MESSAGE)

    verifier = oqs.Signature(ALGORITHM)

    verifier.verify(MESSAGE, signature, public_key)

# -----------------------------------------------------
# Key Generation Benchmark
# -----------------------------------------------------

key_times = []

for _ in range(ITERATIONS):

    signer = oqs.Signature(ALGORITHM)

    start = time.perf_counter_ns()

    public_key = signer.generate_keypair()

    end = time.perf_counter_ns()

    key_times.append(end - start)

# -----------------------------------------------------
# Signing Benchmark
# -----------------------------------------------------

signer = oqs.Signature(ALGORITHM)

public_key = signer.generate_keypair()

sign_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    signature = signer.sign(MESSAGE)

    end = time.perf_counter_ns()

    sign_times.append(end - start)

# -----------------------------------------------------
# Verification Benchmark
# -----------------------------------------------------

verifier = oqs.Signature(ALGORITHM)

signature = signer.sign(MESSAGE)

verify_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    valid = verifier.verify(
        MESSAGE,
        signature,
        public_key
    )

    end = time.perf_counter_ns()

    verify_times.append(end - start)

assert valid

# -----------------------------------------------------
# Results
# -----------------------------------------------------

print("=" * 65)
print("SLH-DSA (SPHINCS+) Benchmark")
print("=" * 65)

print(f"Algorithm        : {ALGORITHM}")
print(f"Iterations       : {ITERATIONS}")
print(f"Message Size     : {len(MESSAGE)} bytes")
print()

print("Key Generation")
print(f"Average : {statistics.mean(key_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(key_times)/1e6:.3f} ms")
print(f"Minimum : {min(key_times)/1e6:.3f} ms")
print(f"Maximum : {max(key_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(key_times)/1e6:.3f} ms")

print()

print("Signature Generation")
print(f"Average : {statistics.mean(sign_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(sign_times)/1e6:.3f} ms")
print(f"Minimum : {min(sign_times)/1e6:.3f} ms")
print(f"Maximum : {max(sign_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(sign_times)/1e6:.3f} ms")

print()

print("Signature Verification")
print(f"Average : {statistics.mean(verify_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(verify_times)/1e6:.3f} ms")
print(f"Minimum : {min(verify_times)/1e6:.3f} ms")
print(f"Maximum : {max(verify_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(verify_times)/1e6:.3f} ms")
