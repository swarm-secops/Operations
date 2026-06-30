import oqs
import os
import time
import statistics

# ----------------------------------------------------
# Parameters
# ----------------------------------------------------

SIG = "ML-DSA-65"

ITERATIONS = 1000
WARMUP = 50

MESSAGE = os.urandom(32)

# ----------------------------------------------------
# Warm-up
# ----------------------------------------------------

for _ in range(WARMUP):

    signer = oqs.Signature(SIG)

    public_key = signer.generate_keypair()

    signature = signer.sign(MESSAGE)

    verifier = oqs.Signature(SIG)

    verifier.verify(MESSAGE, signature, public_key)

# ----------------------------------------------------
# Key Generation
# ----------------------------------------------------

key_times = []

for _ in range(ITERATIONS):

    signer = oqs.Signature(SIG)

    start = time.perf_counter_ns()

    public_key = signer.generate_keypair()

    end = time.perf_counter_ns()

    key_times.append(end - start)

# ----------------------------------------------------
# Signing
# ----------------------------------------------------

signer = oqs.Signature(SIG)

public_key = signer.generate_keypair()

sign_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    signature = signer.sign(MESSAGE)

    end = time.perf_counter_ns()

    sign_times.append(end - start)

# ----------------------------------------------------
# Verification
# ----------------------------------------------------

verifier = oqs.Signature(SIG)

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

# ----------------------------------------------------
# Results
# ----------------------------------------------------

print("="*60)
print(SIG)
print("="*60)

print("\nKey Generation")
print(f"Average : {statistics.mean(key_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(key_times)/1e6:.3f} ms")
print(f"Minimum : {min(key_times)/1e6:.3f} ms")
print(f"Maximum : {max(key_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(key_times)/1e6:.3f} ms")

print("\nSigning")
print(f"Average : {statistics.mean(sign_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(sign_times)/1e6:.3f} ms")
print(f"Minimum : {min(sign_times)/1e6:.3f} ms")
print(f"Maximum : {max(sign_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(sign_times)/1e6:.3f} ms")

print("\nVerification")
print(f"Average : {statistics.mean(verify_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(verify_times)/1e6:.3f} ms")
print(f"Minimum : {min(verify_times)/1e6:.3f} ms")
print(f"Maximum : {max(verify_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(verify_times)/1e6:.3f} ms")