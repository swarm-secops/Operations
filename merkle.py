import hashlib
import os
import time
import statistics

# ---------------- Parameters ----------------
NUM_LEAVES = 1024
ITERATIONS = 1000
WARMUP = 50

# ---------------- Generate Leaves ----------------
leaves = [hashlib.sha256(os.urandom(32)).digest() for _ in range(NUM_LEAVES)]


# ---------------- Build Merkle Tree ----------------
def build_merkle_tree(leaf_nodes):
    tree = [leaf_nodes]
    current = leaf_nodes

    while len(current) > 1:

        if len(current) % 2 == 1:
            current.append(current[-1])

        parent = []

        for i in range(0, len(current), 2):
            parent.append(
                hashlib.sha256(current[i] + current[i + 1]).digest()
            )

        tree.append(parent)
        current = parent

    return tree


# ---------------- Generate Proof ----------------
def merkle_proof(tree, index):

    proof = []

    for level in tree[:-1]:

        if len(level) % 2 == 1:
            level = level + [level[-1]]

        sibling = index ^ 1
        proof.append(level[sibling])

        index //= 2

    return proof


# ---------------- Warm-up ----------------
for _ in range(WARMUP):
    tree = build_merkle_tree(leaves)
    proof = merkle_proof(tree, 100)


# ---------------- Benchmark Tree Build ----------------
build_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    tree = build_merkle_tree(leaves)

    end = time.perf_counter_ns()

    build_times.append(end - start)


# ---------------- Benchmark Proof Generation ----------------
tree = build_merkle_tree(leaves)

proof_times = []

for _ in range(ITERATIONS):

    start = time.perf_counter_ns()

    proof = merkle_proof(tree, 100)

    end = time.perf_counter_ns()

    proof_times.append(end - start)


# ---------------- Results ----------------
print("=" * 60)
print("Merkle Tree Benchmark")
print("=" * 60)

print(f"Leaves          : {NUM_LEAVES}")
print(f"Iterations      : {ITERATIONS}")
print()

print("Tree Construction")
print(f"Average : {statistics.mean(build_times):.2f} ns")
print(f"Median  : {statistics.median(build_times):.2f} ns")
print(f"Minimum : {min(build_times)} ns")
print(f"Maximum : {max(build_times)} ns")

print()

print("Proof Generation")
print(f"Average : {statistics.mean(proof_times):.2f} ns")
print(f"Median  : {statistics.median(proof_times):.2f} ns")
print(f"Minimum : {min(proof_times)} ns")
print(f"Maximum : {max(proof_times)} ns")

print()

print(f"Tree Build Avg : {statistics.mean(build_times)/1e6:.3f} ms")
print(f"Proof Avg      : {statistics.mean(proof_times)/1000:.3f} µs")