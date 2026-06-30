import ctypes
import os
import time
import statistics

# ============================================================
# Load library
# ============================================================
lib = ctypes.CDLL("/home/bnh/Desktop/execute/xorfilter_bench/libxorfilter.so")

# ============================================================
# Function signatures
# All memory management is inside the wrapper —
# Python only sees opaque pointers.
# ============================================================

# XOR8
# xor8_t* wrap_xor8_build(uint64_t *keys, size_t n)
lib.wrap_xor8_build.restype  = ctypes.c_void_p
lib.wrap_xor8_build.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_size_t
]
# int wrap_xor8_contain(xor8_t *f, uint64_t key)
lib.wrap_xor8_contain.restype  = ctypes.c_int
lib.wrap_xor8_contain.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

# size_t wrap_xor8_size_bytes(xor8_t *f)
lib.wrap_xor8_size_bytes.restype  = ctypes.c_size_t
lib.wrap_xor8_size_bytes.argtypes = [ctypes.c_void_p]

# void wrap_xor8_free(xor8_t *f)
lib.wrap_xor8_free.restype  = None
lib.wrap_xor8_free.argtypes = [ctypes.c_void_p]

# XOR16
lib.wrap_xor16_build.restype  = ctypes.c_void_p
lib.wrap_xor16_build.argtypes = [
    ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_size_t
]
lib.wrap_xor16_contain.restype  = ctypes.c_int
lib.wrap_xor16_contain.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

lib.wrap_xor16_size_bytes.restype  = ctypes.c_size_t
lib.wrap_xor16_size_bytes.argtypes = [ctypes.c_void_p]

lib.wrap_xor16_free.restype  = None
lib.wrap_xor16_free.argtypes = [ctypes.c_void_p]

# ============================================================
# Parameters
# ============================================================
BUILD_ITERS  = 1_000
QUERY_ITERS  = 100_000
WARMUP_BUILD = 50
WARMUP_QUERY = 5_000
SET_SIZES    = [100, 500, 1_000, 5_000, 10_000]

# ============================================================
# Helper: unique 64-bit keys as ctypes array
# ============================================================
def generate_keys(n):
    key_set = set()
    while len(key_set) < n:
        key_set.update(
            int.from_bytes(os.urandom(8), 'little')
            for _ in range(n - len(key_set))
        )
    keys = list(key_set)
    arr  = (ctypes.c_uint64 * n)(*keys)
    return keys, arr

# ============================================================
# Report
# ============================================================
def report(label, times, unit_divisor, unit_label):
    avg = statistics.mean(times)
    med = statistics.median(times)
    std = statistics.stdev(times)
    lo  = min(times)
    hi  = max(times)
    p95 = sorted(times)[int(0.95 * len(times))]
    print(f"\n{'─'*62}")
    print(f"  {label}")
    print(f"{'─'*62}")
    print(f"  Average  : {avg/unit_divisor:.4f} {unit_label}  ({avg:.1f} ns)")
    print(f"  Median   : {med/unit_divisor:.4f} {unit_label}  ({med:.1f} ns)")
    print(f"  Std Dev  : {std/unit_divisor:.4f} {unit_label}  ({std:.1f} ns)")
    print(f"  Min      : {lo/unit_divisor:.4f} {unit_label}")
    print(f"  Max      : {hi/unit_divisor:.4f} {unit_label}")
    print(f"  P95      : {p95/unit_divisor:.4f} {unit_label}")

# ============================================================
# Benchmark
# ============================================================
def run_benchmark(n):
    print(f"\n\n{'#'*62}")
    print(f"  Set Size: {n:,} elements")
    print(f"{'#'*62}")

    keys_list, keys_arr = generate_keys(n)
    key_set = set(keys_list)
    arr_ptr = ctypes.cast(keys_arr, ctypes.POINTER(ctypes.c_uint64))

    # Negative keys — guaranteed absent
    neg_list = []
    while len(neg_list) < QUERY_ITERS:
        c = int.from_bytes(os.urandom(8), 'little')
        if c not in key_set:
            neg_list.append(c)

    # Positive keys — cycle through members
    pos_list = (keys_list * (QUERY_ITERS // len(keys_list) + 1))[:QUERY_ITERS]

    for variant, build_fn, contain_fn, size_fn, free_fn, expected_fpr in [
        ("XOR8",
         lib.wrap_xor8_build, lib.wrap_xor8_contain,
         lib.wrap_xor8_size_bytes, lib.wrap_xor8_free,
         0.390625),
        ("XOR16",
         lib.wrap_xor16_build, lib.wrap_xor16_contain,
         lib.wrap_xor16_size_bytes, lib.wrap_xor16_free,
         0.001526),
    ]:
        print(f"\n  [{variant}]")

        # Warmup: Build
        for _ in range(WARMUP_BUILD):
            f = build_fn(arr_ptr, n)
            assert f is not None, f"{variant} build failed during warmup"
            free_fn(f)

        # Benchmark: Build
        # Note: build includes allocate + populate, excludes malloc of struct
        build_times = []
        for _ in range(BUILD_ITERS):
            t0 = time.perf_counter_ns()
            f = build_fn(arr_ptr, n)
            t1 = time.perf_counter_ns()
            assert f is not None, f"{variant} build returned NULL"
            build_times.append(t1 - t0)
            free_fn(f)

        # Build one clean filter for queries
        filt = build_fn(arr_ptr, n)
        assert filt is not None, f"{variant} build failed for query filter"
        sz = size_fn(filt)

        report(f"{variant} Build — {n:,} elements", build_times, 1e6, "ms")
        print(f"  Filter size: {sz:,} bytes  ({sz/n:.2f} bytes/element)")

        # Warmup: Query
        for k in pos_list[:WARMUP_QUERY]:
            contain_fn(filt, k)

        # Benchmark: Positive Query
        pos_times = []
        for k in pos_list:
            t0 = time.perf_counter_ns()
            contain_fn(filt, k)
            t1 = time.perf_counter_ns()
            pos_times.append(t1 - t0)

        report(
            f"{variant} Query (positive — member present) — {n:,} elements",
            pos_times, 1e3, "µs"
        )

        # Benchmark: Negative Query
        neg_times = []
        false_positives = 0
        for k in neg_list:
            t0 = time.perf_counter_ns()
            result = contain_fn(filt, k)
            t1 = time.perf_counter_ns()
            neg_times.append(t1 - t0)
            if result:
                false_positives += 1

        report(
            f"{variant} Query (negative — member absent) — {n:,} elements",
            neg_times, 1e3, "µs"
        )

        fpr = false_positives / QUERY_ITERS * 100
        print(f"  False positive rate: {false_positives}/{QUERY_ITERS} "
              f"= {fpr:.4f}%  (theoretical: ~{expected_fpr:.4f}%)")

        free_fn(filt)

# ============================================================
# Run
# ============================================================
print("=" * 62)
print("  XOR Filter Benchmark (XOR8 + XOR16)")
print("  Backend : xor_singleheader C reference (Graf & Lemire)")
print("  Binding : Python ctypes")
print("  Timer   : time.perf_counter_ns()")
print(f"  Build iterations : {BUILD_ITERS:,}")
print(f"  Query iterations : {QUERY_ITERS:,}")
print("=" * 62)

for n in SET_SIZES:
    run_benchmark(n)

print(f"\n{'='*62}")
print("  XOR8  — 8-bit fingerprints  ~0.39% FPR  ~9.84 bits/elem")
print("  XOR16 — 16-bit fingerprints ~0.0015% FPR ~19.68 bits/elem")
print(f"{'='*62}\n")