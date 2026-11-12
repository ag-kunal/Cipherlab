import hashlib
from qiskit import QuantumCircuit
from qiskit.circuit.library import grover_operator
from qiskit.primitives import StatevectorSampler


def candidate_message(k: int) -> bytes:
    return b"toy-preimage-" + bytes([k])


def phase_oracle(n: int, marked_indices: list[int]) -> QuantumCircuit:
    oracle = QuantumCircuit(n)
    for value in marked_indices:
        for q in range(n):
            if ((value >> q) & 1) == 0:
                oracle.x(q)
        if n == 1:
            oracle.z(0)
        else:
            oracle.h(n - 1)
            oracle.mcx(list(range(n - 1)), n - 1)
            oracle.h(n - 1)
        for q in range(n):
            if ((value >> q) & 1) == 0:
                oracle.x(q)
    return oracle


def main():
    n = 4
    secret_candidate = 9
    target_message = candidate_message(secret_candidate)
    target_digest = hashlib.sha512(target_message).hexdigest()

    # Classically compile the phase oracle by testing all 16 candidate messages
    marked = [
        k for k in range(1 << n)
        if hashlib.sha512(candidate_message(k)).hexdigest() == target_digest
    ]

    print("=== SHA-512 / Grover toy preimage demonstration ===")
    print(f"Target digest (SHA-512 hex): {target_digest}")
    print("Search space: 16 candidate messages with a fixed prefix and 4-bit suffix.")
    print("Oracle marked states:", marked)

    oracle = phase_oracle(n, marked)
    Q = grover_operator(oracle)
    iterations = max(1, round((3.141592653589793 / 4) * ((1 << n) / max(1, len(marked))) ** 0.5))

    qc = QuantumCircuit(n, n)
    qc.h(range(n))
    for _ in range(iterations):
        qc.compose(Q, inplace=True)
    qc.measure(range(n), range(n))

    counts = StatevectorSampler(default_shots=4096, seed=53).run([qc]).result()[0].data.c.get_counts()
    print(f"Grover iterations: {iterations}")
    print("Measured candidate counts:", counts)

    recovered = int(max(counts, key=counts.get).replace(" ", ""), 2)
    recovered_message = candidate_message(recovered)
    recovered_digest = hashlib.sha512(recovered_message).hexdigest()

    print(f"Recovered candidate ID: {recovered}")
    print(f"Recovered candidate message (bytes): {recovered_message!r}")
    print(f"Recovered digest matches target: {recovered_digest == target_digest}")
    print("Verification:", "PASS" if recovered in marked and recovered_digest == target_digest else "FAIL")
    print("Scope: Grover over a classically compiled 4-bit lookup oracle, not a quantum SHA-512 circuit or a practical SHA-512 break.")


if __name__ == "__main__":
    main()
