import oqs
import time
import statistics

# ----------------------------------------------------
# Parameters
# ----------------------------------------------------

KEM = "ML-KEM-768"

ITERATIONS = 1000
WARMUP = 50

# ----------------------------------------------------
# Warm-up
# ----------------------------------------------------

for _ in range(WARMUP):

    sender = oqs.KeyEncapsulation(KEM)

    public_key = sender.generate_keypair()

    ciphertext, ss1 = sender.encap_secret(public_key)

    receiver = oqs.KeyEncapsulation(
        KEM,
        sender.export_secret_key()
    )

    ss2 = receiver.decap_secret(ciphertext)

# ----------------------------------------------------
# Key Generation
# ----------------------------------------------------

key_times = []

for _ in range(ITERATIONS):

    kem = oqs.KeyEncapsulation(KEM)

    start = time.perf_counter_ns()

    public_key = kem.generate_keypair()

    end = time.perf_counter_ns()

    key_times.append(end - start)

# ----------------------------------------------------
# Encapsulation
# ----------------------------------------------------

sender = oqs.KeyEncapsulation(KEM)

public_key = sender.generate_keypair()

encap_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    ciphertext, shared_secret = sender.encap_secret(public_key)

    end = time.perf_counter_ns()

    encap_times.append(end - start)

# ----------------------------------------------------
# Decapsulation
# ----------------------------------------------------

receiver = oqs.KeyEncapsulation(
    KEM,
    sender.export_secret_key()
)

ciphertext, ss1 = sender.encap_secret(public_key)

decap_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    ss2 = receiver.decap_secret(ciphertext)

    end = time.perf_counter_ns()

    decap_times.append(end - start)

assert ss1 == ss2

# ----------------------------------------------------
# Results
# ----------------------------------------------------

print("="*60)
print(KEM)
print("="*60)

print("\nKey Generation")
print(f"Average : {statistics.mean(key_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(key_times)/1e6:.3f} ms")
print(f"Minimum : {min(key_times)/1e6:.3f} ms")
print(f"Maximum : {max(key_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(key_times)/1e6:.3f} ms")

print("\nEncapsulation")
print(f"Average : {statistics.mean(encap_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(encap_times)/1e6:.3f} ms")
print(f"Minimum : {min(encap_times)/1e6:.3f} ms")
print(f"Maximum : {max(encap_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(encap_times)/1e6:.3f} ms")

print("\nDecapsulation")
print(f"Average : {statistics.mean(decap_times)/1e6:.3f} ms")
print(f"Median  : {statistics.median(decap_times)/1e6:.3f} ms")
print(f"Minimum : {min(decap_times)/1e6:.3f} ms")
print(f"Maximum : {max(decap_times)/1e6:.3f} ms")
print(f"Std Dev : {statistics.stdev(decap_times)/1e6:.3f} ms")