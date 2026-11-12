import numpy as np
from fractions import Fraction
from math import gcd

from qiskit import QuantumCircuit
from qiskit.circuit.library import QFTGate, UnitaryGate
from qiskit.primitives import StatevectorSampler


def modular_multiply_unitary(multiplier, N, n_target):
    dim = 1 << n_target
    matrix = np.zeros((dim, dim), dtype=complex)

    for x in range(dim):
        y = (x * multiplier) % N if x < N else x
        matrix[y, x] = 1.0

    return matrix


def build_shor_circuit(a, N, n_count=4):
    n_target = (N - 1).bit_length()
    qc = QuantumCircuit(n_count + n_target, n_count)

    target = list(range(n_count, n_count + n_target))
    qc.h(range(n_count))
    qc.x(target[0])  # Initialize target to |1>

    for j in range(n_count):
        multiplier = pow(a, 1 << j, N)
        unitary = UnitaryGate(
            modular_multiply_unitary(multiplier, N, n_target)
        )
        qc.append(unitary.control(), [j] + target)

    qc.append(QFTGate(n_count).inverse(), range(n_count))
    qc.measure(range(n_count), range(n_count))
    return qc


def main():
    # 1. Classical RSA setup
    p, q = 3, 5
    N = p * q
    phi = (p - 1) * (q - 1)
    e = 7

    original_message = 17
    message = original_message % N

    ciphertext = pow(message, e, N)

    print("=" * 48)
    print("RSA + SHOR: TOY DEMONSTRATION")
    print("=" * 48)
    print(f"Original message       : {original_message}")
    print(f"Normalized message     : {message} (mod {N})")
    print(f"Public key (N, e)      : ({N}, {e})")
    print(f"Ciphertext             : {ciphertext}")
    print(f"Base a                 : 2")
    print(f"Expected period        : 4")

    # 2. Quantum period finding
    a = 2
    assert gcd(a, N) == 1

    circuit = build_shor_circuit(a, N, n_count=4)
    result = StatevectorSampler(
        default_shots=4096, seed=17
    ).run([circuit]).result()

    counts = result[0].data.c.get_counts()
    print("\nMeasurement counts:", counts)

    # 3. Classical post-processing
    candidate_periods = []

    for bits, frequency in counts.items():
        measured = int(bits.replace(" ", ""), 2)
        phase = measured / (1 << 4)

        r0 = Fraction(phase).limit_denominator(N).denominator

        # Try multiples and verify each candidate.
        for multiplier in range(1, N + 1):
            r = r0 * multiplier
            if r > 0 and pow(a, r, N) == 1:
                if r not in candidate_periods:
                    candidate_periods.append(r)
                break

    print("Verified candidate periods:", candidate_periods)

    factors = []
    for r in candidate_periods:
        if r % 2 != 0:
            continue

        x = pow(a, r // 2, N)
        if x in (1, N - 1):
            continue

        for f in (gcd(x - 1, N), gcd(x + 1, N)):
            if 1 < f < N and N % f == 0 and f not in factors:
                factors.append(f)

    factors.sort()
    print("Recovered factors:", factors)

    # 4. Recover RSA private key and decrypt
    if len(factors) >= 2:
        recovered_p, recovered_q = factors[:2]
        recovered_phi = (recovered_p - 1) * (recovered_q - 1)

        recovered_d = pow(e, -1, recovered_phi)
        decrypted = pow(ciphertext, recovered_d, N)

        print(f"Recovered private key d: {recovered_d}")
        print(f"Decrypted message       : {decrypted}")
        print(
            "Verification            :",
            "PASS" if decrypted == message else "FAIL"
        )
        print(
            "Factorization check     :",
            "PASS" if recovered_p * recovered_q == N else "FAIL"
        )
    else:
        print("No usable factors found in this run.")
        print("Try more shots or rerun the simulator.")

    print("\nNote: Toy simulation only; not a real-world RSA attack.")


if __name__ == "__main__":
    main()
