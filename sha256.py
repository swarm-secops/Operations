import hashlib
import os
import time
import statistics

# ---------------- Parameters ----------------
MESSAGE_SIZE = 32      # bytes
ITERATIONS = 10000
WARMUP = 200

# Generate message once
message = os.urandom(MESSAGE_SIZE)

# ---------------- Warm-up ----------------
for _ in range(WARMUP):
    hashlib.sha256(message).digest()

# ---------------- Benchmark ----------------
times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    digest = hashlib.sha256(message).digest()

    end = time.perf_counter_ns()

    times.append(end - start)

# ---------------- Statistics ----------------
avg = statistics.mean(times)
median = statistics.median(times)
minimum = min(times)
maximum = max(times)
std = statistics.stdev(times)

print("=" * 60)
print("SHA-256 Benchmark")
print("=" * 60)
print(f"Message Size     : {MESSAGE_SIZE} bytes")
print(f"Iterations       : {ITERATIONS}")
print()

print(f"Average Time     : {avg:.2f} ns")
print(f"Median Time      : {median:.2f} ns")
print(f"Minimum Time     : {minimum} ns")
print(f"Maximum Time     : {maximum} ns")
print(f"Std. Deviation   : {std:.2f} ns")

print()
print(f"Average = {avg/1000:.3f} µs")
print(f"Average = {avg/1e6:.6f} ms")