import os
import time
import hmac
import hashlib
import statistics

# ============================================================
# Parameters
# ============================================================
ITERATIONS = 1000
WARMUP = 50

KEY_SIZE = 32          # 256-bit key
MESSAGE_SIZE = 32      # 32-byte message

key = os.urandom(KEY_SIZE)
message = os.urandom(MESSAGE_SIZE)

# ============================================================
# Warm-up
# ============================================================
for _ in range(WARMUP):
    hmac.new(key, message, hashlib.sha256).digest()

# ============================================================
# Benchmark
# ============================================================
times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    tag = hmac.new(key, message, hashlib.sha256).digest()

    end = time.perf_counter_ns()

    times.append(end - start)

# ============================================================
# Statistics
# ============================================================
avg = statistics.mean(times)
med = statistics.median(times)
std = statistics.stdev(times)
mn = min(times)
mx = max(times)
p95 = sorted(times)[int(0.95 * len(times))]

# ============================================================
# Report
# ============================================================
print("=" * 60)
print("HMAC-SHA256 Benchmark")
print("=" * 60)
print(f"Message Size : {MESSAGE_SIZE} bytes")
print(f"Key Size     : {KEY_SIZE} bytes")
print(f"Iterations   : {ITERATIONS}")
print(f"Warm-up      : {WARMUP}")
print()

print(f"Average      : {avg/1e6:.6f} ms ({avg:.1f} ns)")
print(f"Median       : {med/1e6:.6f} ms ({med:.1f} ns)")
print(f"Std Dev      : {std/1e6:.6f} ms ({std:.1f} ns)")
print(f"Minimum      : {mn/1e6:.6f} ms")
print(f"Maximum      : {mx/1e6:.6f} ms")
print(f"P95          : {p95/1e6:.6f} ms")

print("\n" + "=" * 60)
print("Backend      : OpenSSL (via Python hashlib/hmac)")
print("Hash         : SHA-256")
print("Timer        : time.perf_counter_ns()")
print("=" * 60)