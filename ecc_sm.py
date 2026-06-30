# USING C IMPLEMENTATION
import ctypes
import ctypes.util
import os
import time
import statistics

# ============================================================
# Load OpenSSL
# ============================================================
ssl_lib_name = ctypes.util.find_library("ssl")
crypto_lib_name = ctypes.util.find_library("crypto")

libssl    = ctypes.CDLL(ssl_lib_name)
libcrypto = ctypes.CDLL(crypto_lib_name)

# ============================================================
# OpenSSL constants and function signatures
# ============================================================
NID_X9_62_prime256v1 = 415  # NIST P-256

# EC_GROUP
libcrypto.EC_GROUP_new_by_curve_name.restype  = ctypes.c_void_p
libcrypto.EC_GROUP_new_by_curve_name.argtypes = [ctypes.c_int]
libcrypto.EC_GROUP_free.argtypes              = [ctypes.c_void_p]

# EC_POINT
libcrypto.EC_POINT_new.restype   = ctypes.c_void_p
libcrypto.EC_POINT_new.argtypes  = [ctypes.c_void_p]
libcrypto.EC_POINT_free.argtypes = [ctypes.c_void_p]

# EC_POINT_mul: R = n*G + m*Q (we use m=NULL for pure scalar mul: R = n*G)
libcrypto.EC_POINT_mul.restype  = ctypes.c_int
libcrypto.EC_POINT_mul.argtypes = [
    ctypes.c_void_p,  # group
    ctypes.c_void_p,  # result point R
    ctypes.c_void_p,  # n (BIGNUM) — scalar for G
    ctypes.c_void_p,  # Q (EC_POINT) — NULL for fixed-base only
    ctypes.c_void_p,  # m (BIGNUM)  — NULL for fixed-base only
    ctypes.c_void_p,  # ctx (BN_CTX)
]

# BIGNUM
libcrypto.BN_new.restype          = ctypes.c_void_p
libcrypto.BN_free.argtypes        = [ctypes.c_void_p]
libcrypto.BN_bin2bn.restype       = ctypes.c_void_p
libcrypto.BN_bin2bn.argtypes      = [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p]
libcrypto.BN_rand.restype         = ctypes.c_int
libcrypto.BN_rand.argtypes        = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]

# BN_CTX
libcrypto.BN_CTX_new.restype    = ctypes.c_void_p
libcrypto.BN_CTX_free.argtypes  = [ctypes.c_void_p]

# EC_POINT_get_affine_coordinates to force full computation
libcrypto.EC_POINT_get_affine_coordinates.restype  = ctypes.c_int
libcrypto.EC_POINT_get_affine_coordinates.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p
]

# ============================================================
# Setup: group, result point, BN_CTX
# ============================================================
group  = libcrypto.EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)
result = libcrypto.EC_POINT_new(group)
ctx    = libcrypto.BN_CTX_new()
scalar = libcrypto.BN_new()
x_out  = libcrypto.BN_new()
y_out  = libcrypto.BN_new()

assert group  != 0, "Failed to create EC_GROUP"
assert result != 0, "Failed to create EC_POINT"
assert ctx    != 0, "Failed to create BN_CTX"
assert scalar != 0, "Failed to create BIGNUM"

# ============================================================
# Parameters
# ============================================================
ITERATIONS = 1000
WARMUP     = 50

# ============================================================
# Helper: generate a fresh random 256-bit scalar
# ============================================================
def new_random_scalar():
    bn = libcrypto.BN_new()
    libcrypto.BN_rand(bn, 256, -1, 0)  # -1 = no top-bit constraint
    return bn

# ============================================================
# Warm-up — use fresh scalars each time (variable-base warmup)
# ============================================================
print("Warming up...")
for _ in range(WARMUP):
    s = new_random_scalar()
    libcrypto.EC_POINT_mul(group, result, s, None, None, ctx)
    libcrypto.EC_POINT_get_affine_coordinates(group, result, x_out, y_out, ctx)
    libcrypto.BN_free(s)

# ============================================================
# Benchmark A: Fixed-Base Scalar Multiplication  (k * G)
# The base point G is fixed; OpenSSL uses precomputed tables.
# This is what ECDSA signing uses internally.
# ============================================================
print("Benchmarking fixed-base scalar multiplication (k*G)...")
fixed_times = []
for _ in range(ITERATIONS):
    s = new_random_scalar()
    t0 = time.perf_counter_ns()
    libcrypto.EC_POINT_mul(group, result, s, None, None, ctx)
    # Force affine conversion — projective coords are lazy otherwise
    libcrypto.EC_POINT_get_affine_coordinates(group, result, x_out, y_out, ctx)
    t1 = time.perf_counter_ns()
    fixed_times.append(t1 - t0)
    libcrypto.BN_free(s)

# ============================================================
# Benchmark B: Variable-Base Scalar Multiplication  (k * P)
# The point P is arbitrary; no precomputation possible.
# This is what ECDH and ECDSA verification use internally.
# ============================================================

# Generate a fixed arbitrary point P = r*G for variable-base test
r  = new_random_scalar()
P  = libcrypto.EC_POINT_new(group)
libcrypto.EC_POINT_mul(group, P, r, None, None, ctx)
libcrypto.BN_free(r)

print("Benchmarking variable-base scalar multiplication (k*P)...")
variable_times = []
for _ in range(ITERATIONS):
    s = new_random_scalar()
    t0 = time.perf_counter_ns()
    libcrypto.EC_POINT_mul(group, result, None, P, s, ctx)
    libcrypto.EC_POINT_get_affine_coordinates(group, result, x_out, y_out, ctx)
    t1 = time.perf_counter_ns()
    variable_times.append(t1 - t0)
    libcrypto.BN_free(s)

# ============================================================
# Cleanup
# ============================================================
libcrypto.EC_POINT_free(result)
libcrypto.EC_POINT_free(P)
libcrypto.BN_free(scalar)
libcrypto.BN_free(x_out)
libcrypto.BN_free(y_out)
libcrypto.BN_CTX_free(ctx)
libcrypto.EC_GROUP_free(group)

# ============================================================
# Report
# ============================================================
def report(label, times):
    avg = statistics.mean(times)
    med = statistics.median(times)
    std = statistics.stdev(times)
    lo  = min(times)
    hi  = max(times)
    p95 = sorted(times)[int(0.95 * len(times))]
    print(f"\n{'─'*60}")
    print(f"  {label}")
    print(f"{'─'*60}")
    print(f"  Average  : {avg/1e6:.4f} ms  ({avg:.1f} ns)")
    print(f"  Median   : {med/1e6:.4f} ms  ({med:.1f} ns)")
    print(f"  Std Dev  : {std/1e6:.4f} ms  ({std:.1f} ns)")
    print(f"  Min      : {lo/1e6:.4f} ms")
    print(f"  Max      : {hi/1e6:.4f} ms")
    print(f"  P95      : {p95/1e6:.4f} ms")

print("\n" + "="*60)
print("  EC Scalar Multiplication — NIST P-256 (secp256r1)")
print("  Via direct OpenSSL EC_POINT_mul() call")
print(f"  Iterations: {ITERATIONS:,}   Warmup: {WARMUP:,}")
print("="*60)

report("Fixed-Base  k*G  (base point G — ECDSA signing path)", fixed_times)
report("Variable-Base k*P (arbitrary point P — ECDH/verify path)", variable_times)

print(f"\n{'='*60}")
print("  Method: ctypes → libcrypto → EC_POINT_mul()")
print("  Affine coordinates forced after each mul to prevent")
print("  lazy projective evaluation from distorting timings.")
print(f"{'='*60}\n")
