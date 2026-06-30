# USING ECDSA
import secrets
import time
import statistics

from ecdsa.curves import NIST256p

# ---------------- Parameters ----------------
ITERATIONS = 1000
WARMUP = 50

curve = NIST256p
G = curve.generator
order = curve.order

# Generate all scalars beforehand (not included in timing)
scalars = [secrets.randbelow(order - 1) + 1 for _ in range(ITERATIONS)]

# ---------------- Warm-up ----------------
for i in range(WARMUP):
    _ = scalars[i] * G

# ---------------- Benchmark ----------------
times = []

for k in scalars:

    start = time.perf_counter_ns()

    Q = k * G          # <-- Only scalar multiplication is timed

    end = time.perf_counter_ns()

    times.append(end - start)

# ---------------- Results ----------------
avg = statistics.mean(times)
median = statistics.median(times)
minimum = min(times)
maximum = max(times)
std = statistics.stdev(times)

print("=" * 60)
print("Elliptic Curve Scalar Multiplication Benchmark")
print("=" * 60)
print(f"Curve           : NIST P-256")
print(f"Scalar Size     : 256 bits")
print(f"Iterations      : {ITERATIONS}")
print()

print(f"Average Time    : {avg:.2f} ns")
print(f"Median Time     : {median:.2f} ns")
print(f"Minimum Time    : {minimum} ns")
print(f"Maximum Time    : {maximum} ns")
print(f"Std. Deviation  : {std:.2f} ns")

print()
print(f"Average = {avg/1000:.3f} us")
print(f"Average = {avg/1e6:.6f} ms")
