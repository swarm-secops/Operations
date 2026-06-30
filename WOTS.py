import hashlib
import secrets
import time
import statistics
import math

# ---------------- Parameters ----------------
n = 32                  # SHA-256 output size (bytes)
w = 16                  # Winternitz parameter

len1 = math.ceil((8 * n) / math.log2(w))
len2 = math.floor(math.log2(len1 * (w - 1)) / math.log2(w)) + 1
L = len1 + len2

ITERATIONS = 1000
WARMUP = 50


# ---------------- SHA-256 ----------------
def H(x):
    return hashlib.sha256(x).digest()


# ---------------- Hash Chain ----------------
def hash_chain(x, steps):
    y = x
    for _ in range(steps):
        y = H(y)
    return y


# ---------------- Base-w Conversion ----------------
def base_w(msg, w, out_len):
    digits = []

    total = int.from_bytes(msg, 'big')

    while total > 0:
        digits.append(total % w)
        total //= w

    digits = digits[::-1]

    while len(digits) < out_len:
        digits.insert(0, 0)

    return digits[-out_len:]


# ---------------- Checksum ----------------
def checksum(msg_digits):

    csum = sum((w - 1 - d) for d in msg_digits)

    out = []

    while csum > 0:
        out.append(csum % w)
        csum //= w

    while len(out) < len2:
        out.append(0)

    return out[::-1]


# ---------------- Key Generation ----------------
def keygen():

    sk = [secrets.token_bytes(n) for _ in range(L)]

    pk = [hash_chain(x, w - 1) for x in sk]

    return sk, pk


# ---------------- Sign ----------------
def sign(sk, message):

    digest = hashlib.sha256(message).digest()

    msg_digits = base_w(digest, w, len1)

    digits = msg_digits + checksum(msg_digits)

    sig = [
        hash_chain(sk[i], digits[i])
        for i in range(L)
    ]

    return sig


# ---------------- Verify ----------------
def verify(pk, sig, message):

    digest = hashlib.sha256(message).digest()

    msg_digits = base_w(digest, w, len1)

    digits = msg_digits + checksum(msg_digits)

    computed = [
        hash_chain(sig[i], (w - 1) - digits[i])
        for i in range(L)
    ]

    return computed == pk


# --------------------------------------------------
# Warm-up
# --------------------------------------------------

message = b"Hello Raspberry Pi"

for _ in range(WARMUP):
    sk, pk = keygen()
    sig = sign(sk, message)
    verify(pk, sig, message)

# --------------------------------------------------
# Key Generation Benchmark
# --------------------------------------------------

key_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    sk, pk = keygen()

    end = time.perf_counter_ns()

    key_times.append(end - start)

# --------------------------------------------------
# Signing Benchmark
# --------------------------------------------------

sk, pk = keygen()

sign_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    sig = sign(sk, message)

    end = time.perf_counter_ns()

    sign_times.append(end - start)

# --------------------------------------------------
# Verification Benchmark
# --------------------------------------------------

sig = sign(sk, message)

verify_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    verify(pk, sig, message)

    end = time.perf_counter_ns()

    verify_times.append(end - start)

# --------------------------------------------------
# Results
# --------------------------------------------------

print("="*60)
print("WOTS Benchmark")
print("="*60)

print(f"Chains           : {L}")
print(f"Winternitz w     : {w}")
print(f"Iterations       : {ITERATIONS}")
print()

print("Key Generation")
print(f"Average : {statistics.mean(key_times)/1e6:.3f} ms")

print()

print("Signing")
print(f"Average : {statistics.mean(sign_times)/1e6:.3f} ms")

print()

print("Verification")
print(f"Average : {statistics.mean(verify_times)/1e6:.3f} ms")