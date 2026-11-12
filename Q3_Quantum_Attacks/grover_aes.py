from Crypto.Cipher import AES
from qiskit import QuantumCircuit
from qiskit.circuit.library import grover_operator
from qiskit.primitives import StatevectorSampler


def candidate_key(k: int) -> bytes:
    # 15 zero bytes followed by a 4-bit candidate byte.
    return bytes(15) + bytes([k])


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def phase_oracle(n: int, marked_indices: list[int]) -> QuantumCircuit:
    oracle = QuantumCircuit(n)
    for value in marked_indices:
        # Convert |value> to |11...1>, apply phase -1, then undo X gates.
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


def run_grover(n: int, marked_indices: list[int], shots: int = 4096):
    oracle = phase_oracle(n, marked_indices)
    Q = grover_operator(oracle)
    iterations = max(1, round((3.141592653589793 / 4) * ((1 << n) / max(1, len(marked_indices))) ** 0.5))
    qc = QuantumCircuit(n, n)
    qc.h(range(n))
    for _ in range(iterations):
        qc.compose(Q, inplace=True)
    qc.measure(range(n), range(n))
    counts = StatevectorSampler(default_shots=shots, seed=41).run([qc]).result()[0].data.c.get_counts()
    return counts, iterations


def main():
    n = 4
    secret_candidate = 11
    plaintext = b"Toy AES demo!!!!"  # one AES block (16 bytes)
    target_ciphertext = encrypt(candidate_key(secret_candidate), plaintext)

    # Classically compile a lookup oracle by checking the actual AES verifier
    marked = [
        k for k in range(1 << n)
        if encrypt(candidate_key(k), plaintext) == target_ciphertext
    ]

    print("=== AES-128 / Grover toy demonstration ===")
    print(f"Plaintext (hex): {plaintext.hex()}")
    print(f"Target ciphertext (hex): {target_ciphertext.hex()}")
    print("Search space: 16 candidate keys, each embedded in a restricted 128-bit key family.")
    print("Oracle marked states:", marked)

    counts, iterations = run_grover(n, marked)
    print(f"Grover iterations: {iterations}")
    print("Measured candidate counts:", counts)
    recovered = int(max(counts, key=counts.get).replace(" ", ""), 2)
    recovered_key = candidate_key(recovered)
    decrypted = AES.new(recovered_key, AES.MODE_ECB).decrypt(target_ciphertext)

    print(f"Recovered candidate ID: {recovered}")
    print(f"Recovered restricted AES key (hex): {recovered_key.hex()}")
    print(f"Decrypted plaintext (hex): {decrypted.hex()}")
    print("Verification:", "PASS" if recovered in marked and decrypted == plaintext else "FAIL")
    print("Scope: Grover over a classically compiled 4-bit lookup oracle, not a quantum AES-128 circuit or a practical AES break.")


if __name__ == "__main__":
    main()
