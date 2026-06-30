import ctypes
import os
import time
import statistics

# ============================================================
# Load library
# ============================================================
lib = ctypes.CDLL("/home/bnh/Desktop/execute/sphincsplus/ref/libfors.so")

# ============================================================
# Exact sizes from params-sphincs-sha2-128f.h
# SPX_N=16, SPX_SHA512=0, SPX_FORS_HEIGHT=6, SPX_FORS_TREES=33
# ============================================================
SPX_N              = 16
SPX_FORS_HEIGHT    = 6
SPX_FORS_TREES     = 33
SPX_FORS_MSG_BYTES = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) // 8  # = 25
SPX_FORS_BYTES     = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N  # = 3696
SPX_FORS_PK_BYTES  = SPX_N  # = 16
SPX_ADDR_BYTES     = 32     # uint8_t[32] per SPX_ADDR_BYTES define

# ============================================================
# spx_ctx struct — exact layout from context.h
# SHA2 variant, SPX_SHA512=0:
#   uint8_t pub_seed[16]
#   uint8_t sk_seed[16]
#   uint8_t state_seeded[40]   (SHA2 only, SHA512=0 so no state_seeded_512)
# ============================================================
class SpxCtx(ctypes.Structure):
    _fields_ = [
        ("pub_seed",     ctypes.c_uint8 * SPX_N),   # 16 bytes
        ("sk_seed",      ctypes.c_uint8 * SPX_N),   # 16 bytes
        ("state_seeded", ctypes.c_uint8 * 40),       # 40 bytes (SHA-256 state)
    ]

# ============================================================
# Address: uint8_t[32] per SPX_ADDR_BYTES
# ============================================================
AddrType = ctypes.c_uint8 * SPX_ADDR_BYTES

# ============================================================
# Function signatures
# void SPX_fors_sign(uint8_t *sig, uint8_t *pk,
#                    const uint8_t *m,
#                    const spx_ctx *ctx,
#                    const uint8_t addr[32]);
#
# void SPX_fors_pk_from_sig(uint8_t *pk,
#                            const uint8_t *sig,
#                            const uint8_t *m,
#                            const spx_ctx *ctx,
#                            const uint8_t addr[32]);
# ============================================================
lib.SPX_fors_sign.restype  = None
lib.SPX_fors_sign.argtypes = [
    ctypes.c_char_p,            # sig output
    ctypes.c_char_p,            # pk output
    ctypes.c_char_p,            # message input
    ctypes.POINTER(SpxCtx),     # context
    ctypes.POINTER(ctypes.c_uint8),  # addr[32]
]

lib.SPX_fors_pk_from_sig.restype  = None
lib.SPX_fors_pk_from_sig.argtypes = [
    ctypes.c_char_p,            # pk output (recovered)
    ctypes.c_char_p,            # sig input
    ctypes.c_char_p,            # message input
    ctypes.POINTER(SpxCtx),     # context
    ctypes.POINTER(ctypes.c_uint8),  # addr[32]
]

# ============================================================
# Parameters
# ============================================================
ITERATIONS = 1000
WARMUP     = 50

# ============================================================
# Setup
# ============================================================
ctx = SpxCtx()
raw_pub = os.urandom(SPX_N)
raw_sk  = os.urandom(SPX_N)
ctx.pub_seed[:] = list(raw_pub)
ctx.sk_seed[:]  = list(raw_sk)
# state_seeded must be initialized properly —
# in the real library this is done by SPX_initialize_hash_function()
# We call it if available, otherwise zero-init is safe for benchmarking
# since we are measuring time, not producing valid cryptographic output
ctx.state_seeded[:] = [0] * 40

message = os.urandom(SPX_FORS_MSG_BYTES)   # 25 bytes
addr    = AddrType(*([0] * SPX_ADDR_BYTES))

sig_buf = ctypes.create_string_buffer(SPX_FORS_BYTES)     # 3696 bytes
pk_buf  = ctypes.create_string_buffer(SPX_FORS_PK_BYTES)  # 16 bytes
pk_rec  = ctypes.create_string_buffer(SPX_FORS_PK_BYTES)  # 16 bytes

ctx_ptr  = ctypes.pointer(ctx)
addr_ptr = ctypes.cast(addr, ctypes.POINTER(ctypes.c_uint8))

# ============================================================
# Initialize hash state properly via SPX_initialize_hash_function
# This seeds state_seeded from pub_seed — required before any call
# ============================================================
try:
    lib.SPX_initialize_hash_function.restype  = None
    lib.SPX_initialize_hash_function.argtypes = [ctypes.POINTER(SpxCtx)]
    lib.SPX_initialize_hash_function(ctx_ptr)
    print("Hash function initialized via SPX_initialize_hash_function")
except AttributeError:
    print("WARNING: SPX_initialize_hash_function not found — state_seeded zeroed")

# ============================================================
# Warm-up
# ============================================================
print("Warming up...")
for _ in range(WARMUP):
    lib.SPX_fors_sign(sig_buf, pk_buf, message, ctx_ptr, addr_ptr)
    lib.SPX_fors_pk_from_sig(pk_rec, sig_buf, message, ctx_ptr, addr_ptr)

# ============================================================
# Benchmark: FORS Sign
# ============================================================
print(f"Benchmarking FORS sign ({ITERATIONS:,} iterations)...")
sign_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    lib.SPX_fors_sign(sig_buf, pk_buf, message, ctx_ptr, addr_ptr)
    t1 = time.perf_counter_ns()
    sign_times.append(t1 - t0)

# ============================================================
# Benchmark: FORS pk_from_sig (verify)
# ============================================================
lib.SPX_fors_sign(sig_buf, pk_buf, message, ctx_ptr, addr_ptr)

print(f"Benchmarking FORS pk_from_sig ({ITERATIONS:,} iterations)...")
verify_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    lib.SPX_fors_pk_from_sig(pk_rec, sig_buf, message, ctx_ptr, addr_ptr)
    t1 = time.perf_counter_ns()
    verify_times.append(t1 - t0)

# ============================================================
# Sanity check
# ============================================================
assert pk_rec.raw == pk_buf.raw, \
    "FORS PK recovery mismatch — check struct layout or buffer sizes"
print("Sanity check passed: recovered PK matches original PK")

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
    print(f"\n{'─'*62}")
    print(f"  {label}")
    print(f"{'─'*62}")
    print(f"  Average  : {avg/1e6:.4f} ms  ({avg:.1f} ns)")
    print(f"  Median   : {med/1e6:.4f} ms  ({med:.1f} ns)")
    print(f"  Std Dev  : {std/1e6:.4f} ms  ({std:.1f} ns)")
    print(f"  Min      : {lo/1e6:.4f} ms")
    print(f"  Max      : {hi/1e6:.4f} ms")
    print(f"  P95      : {p95/1e6:.4f} ms")

print("\n" + "="*62)
print("  FORS Benchmark — sphincs-sha2-128f")
print(f"  k={SPX_FORS_TREES} trees, a={SPX_FORS_HEIGHT}, "
      f"t=2^{SPX_FORS_HEIGHT}={2**SPX_FORS_HEIGHT} leaves/tree")
print(f"  Sig size : {SPX_FORS_BYTES} bytes")
print(f"  Msg size : {SPX_FORS_MSG_BYTES} bytes")
print(f"  Iterations: {ITERATIONS:,}   Warmup: {WARMUP:,}")
print("="*62)

report("FORS Sign      — SPX_fors_sign()", sign_times)
report("FORS Verify    — SPX_fors_pk_from_sig()", verify_times)

print(f"\n{'='*62}")
print("  Backend  : SPHINCS+ NIST reference C implementation")
print("  Binding  : Python ctypes")
print("  Timer    : time.perf_counter_ns()")
print("  Compiler : gcc -O2 -shared -fPIC")
print(f"{'='*62}\n")
