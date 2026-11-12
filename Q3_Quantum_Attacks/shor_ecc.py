import numpy as np

from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit.circuit.library import QFTGate, UnitaryGate
from qiskit.primitives import StatevectorSampler


INF = None

# Elliptic-curve arithmetic

def inv_mod(x, p):
    """Multiplicative inverse of x modulo prime p."""
    x %= p

    if x == 0:
        raise ZeroDivisionError("0 has no modular inverse")

    return pow(x, -1, p)


def ec_add(P, Q, a, p):
    """
    Add two points on the curve:

        y^2 = x^3 + a*x + b (mod p)

    The coefficient b is not needed explicitly in the addition formulas.
    """

    if P is INF:
        return Q

    if Q is INF:
        return P

    x1, y1 = P
    x2, y2 = Q

    # A point plus its inverse equals the point at infinity.
    if x1 == x2 and (y1 + y2) % p == 0:
        return INF

    if P == Q:
        # Point doubling.
        if y1 % p == 0:
            return INF

        slope = (
            (3 * x1 * x1 + a) * inv_mod(2 * y1, p)
        ) % p

    else:
        # Addition of two distinct points.
        slope = (
            (y2 - y1) * inv_mod(x2 - x1, p)
        ) % p

    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p

    return x3, y3


def ec_mul(k, P, a, p):
    """Scalar multiplication using double-and-add."""

    if k < 0:
        raise ValueError("This demonstration expects k >= 0")

    result = INF
    addend = P

    while k > 0:

        if k & 1:
            result = ec_add(result, addend, a, p)

        addend = ec_add(addend, addend, a, p)
        k >>= 1

    return result


# Find a toy curve with a point of order 8

def find_order_8_curve():

    for p in (17, 19, 23, 29, 31, 37, 41):

        for a in range(p):

            for b in range(p):

                # Nonsingular curve condition:
                # 4*a^3 + 27*b^2 must not equal 0 modulo p.
                if (4 * a**3 + 27 * b**2) % p == 0:
                    continue

                points = [INF]

                # Enumerate all affine points on the curve.
                for x in range(p):

                    for y in range(p):

                        if (
                            y * y - x**3 - a * x - b
                        ) % p == 0:

                            points.append((x, y))

                # Find a point whose order is exactly 8.
                for G in points[1:]:

                    if (
                        ec_mul(8, G, a, p) is INF
                        and all(
                            ec_mul(k, G, a, p) is not INF
                            for k in (1, 2, 4)
                        )
                    ):

                        return p, a, b, G, points

    raise RuntimeError("No suitable toy curve found.")


# Build a quantum translation unitary

def translation_unitary(
    T,
    point_to_index,
    index_to_point,
    a,
    p,
    n_point,
):
    """
    Construct a permutation matrix implementing:

        |P> -> |P + T>

    Valid curve points are encoded as computational basis states.
    Unused binary encodings remain unchanged.
    """

    dim = 1 << n_point
    U = np.zeros((dim, dim), dtype=complex)

    valid_count = len(index_to_point)

    for idx in range(dim):

        if idx < valid_count:

            point = index_to_point[idx]

            translated = ec_add(
                point,
                T,
                a,
                p,
            )

            out_idx = point_to_index[translated]

        else:

            # Preserve unused binary encodings.
            out_idx = idx

        U[out_idx, idx] = 1.0

    return U


# Build the toy ECC Fourier-sampling circuit

def build_ecc_circuit(
    p,
    a,
    G,
    Q,
    points,
    order=8,
):
    """
    Construct a circuit for the function:

        f(u, v) = u*G + v*Q

    If Q = d*G, inverse-QFT measurement outcomes satisfy:

        v = d*u (mod order)

    This implementation expects a power-of-two point order.
    """

    if order < 2:
        raise ValueError("order must be at least 2")

    if order & (order - 1):
        raise ValueError(
            "This implementation currently expects a power-of-two point order."
        )

    n_count = (order - 1).bit_length()

    index_to_point = list(points)

    point_to_index = {
        point: i
        for i, point in enumerate(index_to_point)
    }

    # Number of qubits required to encode every curve point.
    n_point = (len(index_to_point) - 1).bit_length()

    reg_u = QuantumRegister(n_count, "reg_u")
    reg_v = QuantumRegister(n_count, "reg_v")
    target = QuantumRegister(n_point, "target")

    # One classical register stores BOTH measurement results.
    c = ClassicalRegister(2 * n_count, "c")

    qc = QuantumCircuit(
        reg_u,
        reg_v,
        target,
        c,
    )

    # Put both counting registers into uniform superposition.
    qc.h(reg_u)
    qc.h(reg_v)

    # Reversibly compute u*G + v*Q in the target register.
    # The point at infinity is encoded as index 0, corresponding to |0...0>.
    for j in range(n_count):

        scalar = 1 << j

        # Controlled addition of 2^j * G.
        T_G = ec_mul(
            scalar,
            G,
            a,
            p,
        )

        U_G = UnitaryGate(
            translation_unitary(
                T_G,
                point_to_index,
                index_to_point,
                a,
                p,
                n_point,
            ),
            label=f"Add_{scalar}G",
        )

        qc.append(
            U_G.control(),
            [reg_u[j]] + list(target),
        )

        # Controlled addition of 2^j * Q.
        T_Q = ec_mul(
            scalar,
            Q,
            a,
            p,
        )

        U_Q = UnitaryGate(
            translation_unitary(
                T_Q,
                point_to_index,
                index_to_point,
                a,
                p,
                n_point,
            ),
            label=f"Add_{scalar}Q",
        )

        qc.append(
            U_Q.control(),
            [reg_v[j]] + list(target),
        )

    # Apply inverse quantum Fourier transforms.
    qc.append(
        QFTGate(n_count).inverse(),
        list(reg_u),
    )

    qc.append(
        QFTGate(n_count).inverse(),
        list(reg_v),
    )

    # Store both measurement results in classical register c.
    # c[0:3] stores u.
    # c[3:6] stores v.
    qc.measure(
        reg_u,
        list(range(n_count)),
    )

    qc.measure(
        reg_v,
        list(range(n_count, 2 * n_count)),
    )

    return qc


def main():

    p, a, b, G, points = find_order_8_curve()

    order = 8

    # Known scalar used only to construct and verify the toy public key.
    secret_d = 3

    # Public key: Q = d*G.
    Q = ec_mul(
        secret_d,
        G,
        a,
        p,
    )

    print("=" * 58)
    print("TOY ECC DISCRETE-LOG FOURIER-SAMPLING DEMONSTRATION")
    print("=" * 58)

    print(f"Curve equation: y^2 = x^3 + {a}x + {b} mod {p}")
    print(f"Base point G  : {G}")
    print(f"Base order    : {order}")
    print(f"Public point Q: {Q}")

    print(
        "Reference secret scalar (verification only):",
        secret_d,
    )

    # Build circuit.
    circuit = build_ecc_circuit(
        p,
        a,
        G,
        Q,
        points,
        order,
    )

    print("Circuit qubits:", circuit.num_qubits)

    sampler = StatevectorSampler(
        default_shots=4096,
        seed=29,
    )

    sampler_result = sampler.run(
        [circuit]
    ).result()


    joint_counts = sampler_result[0].data.c.get_counts()

    print("\nMeasured joint outcomes:")
    print(joint_counts)

    candidates = {}

    n_count = (order - 1).bit_length()
    mask = (1 << n_count) - 1


    for bitstring, frequency in joint_counts.items():

        # Qiskit displays the highest classical bit on the left
        # c[0] is the lsb
        value = int(
            bitstring.replace(" ", ""),
            2,
        )

        # First counting register.
        u = value & mask

        # Second counting register.
        v = (value >> n_count) & mask

        # For Q = d*G, the inverse-QFT samples satisfy:
        #  v = d*u (mod order)
        # Odd u is invertible modulo 8.
        if u % 2 == 1:

            d_candidate = (
                v * pow(u, -1, order)
            ) % order


            if ec_mul(
                d_candidate,
                G,
                a,
                p,
            ) == Q:

                candidates[d_candidate] = (
                    candidates.get(d_candidate, 0)
                    + frequency
                )

    print(
        "\nVerified scalar candidates and supporting shot counts:",
        candidates,
    )

    if candidates:

        recovered_d = max(
            candidates,
            key=candidates.get,
        )

        valid = (
            ec_mul(
                recovered_d,
                G,
                a,
                p,
            ) == Q
        )

        print("Recovered private scalar:", recovered_d)

        print(
            "Public-key verification:",
            "PASS" if valid else "FAIL",
        )

    else:

        print(
            "No scalar was recovered from these samples. "
            "Try increasing shots."
        )

    print(
        "\nNote: this uses a tiny curve and dense simulated "
        "point-translation matrices."
    )

    print(
        "It illustrates Fourier sampling, not a practical "
        "ECC-breaking implementation."
    )


if __name__ == "__main__":
    main()
