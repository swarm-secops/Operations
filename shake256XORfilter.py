import hashlib
import os
import time
import statistics

# ---------------- Parameters ----------------
MESSAGE_SIZE = 32      # bytes
OUTPUT_SIZE = 32       # 256-bit digest
ITERATIONS = 1000
WARMUP = 50

# Generate message once
message = os.urandom(MESSAGE_SIZE)

# ---------------- Warm-up ----------------
for _ in range(WARMUP):
    hashlib.shake_256(message).digest(OUTPUT_SIZE)

# ---------------- Benchmark ----------------
times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    digest = hashlib.shake_256(message).digest(OUTPUT_SIZE)

    end = time.perf_counter_ns()

    times.append(end - start)

# ---------------- Statistics ----------------
avg = statistics.mean(times)
median = statistics.median(times)
minimum = min(times)
maximum = max(times)
std = statistics.stdev(times)

print("=" * 60)
print("SHAKE-256 Benchmark")
print("=" * 60)
print(f"Message Size     : {MESSAGE_SIZE} bytes")
print(f"Output Size      : {OUTPUT_SIZE} bytes")
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
