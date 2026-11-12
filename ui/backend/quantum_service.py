import hashlib
import math
import sys
import time
from fractions import Fraction
from math import gcd
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from Crypto.Cipher import AES
from qiskit import QuantumCircuit
from qiskit.circuit.library import grover_operator
from qiskit.primitives import StatevectorSampler

REPO_ROOT = Path(__file__).resolve().parents[2]
Q3_DIR = REPO_ROOT / "Q3_Quantum_Attacks"
if str(Q3_DIR) not in sys.path:
    sys.path.insert(0, str(Q3_DIR))

import grover_aes  # noqa: E402
import grover_sha512  # noqa: E402
import shor_ecc  # noqa: E402
import shor_rsa  # noqa: E402


# Cache the toy order-8 curve from shor_ecc so repeated calls are instant.
_ORDER_8_CURVE = shor_ecc.find_order_8_curve()


def get_toy_ecc_info() -> Dict[str, Any]:
    p, a, b, G, points = _ORDER_8_CURVE
    subgroup = []
    for k in range(1, 8):
        pt = shor_ecc.ec_mul(k, G, a, p)
        subgroup.append({"k": k, "point": [pt[0], pt[1]]})
    return {
        "p": p,
        "a": a,
        "b": b,
        "G": [G[0], G[1]],
        "order": 8,
        "total_points": len(points),
        "subgroup": subgroup,
    }


def _encode_text_chunks(text: str, N: int) -> Tuple[List[int], str]:
    raw = text.encode("utf-8")
    if N >= 21:
        # Each byte splits into two 4-bit nibbles (0..15), all strictly < N.
        chunks: List[int] = []
        for byte in raw:
            chunks.append(byte >> 4)
            chunks.append(byte & 0x0F)
        return chunks, "4-bit nibble"
    # For N == 15, split each byte into three 3-bit octal chunks (0..7), all < 15.
    chunks = []
    for byte in raw:
        chunks.append((byte >> 6) & 0x03)
        chunks.append((byte >> 3) & 0x07)
        chunks.append(byte & 0x07)
    return chunks, "3-bit octal"


def _decode_text_chunks(chunks: List[int], mode: str) -> str:
    out = bytearray()
    if mode == "4-bit nibble":
        for i in range(0, len(chunks) - 1, 2):
            out.append(((chunks[i] & 0x0F) << 4) | (chunks[i + 1] & 0x0F))
    else:
        for i in range(0, len(chunks) - 2, 3):
            b = ((chunks[i] & 0x03) << 6) | ((chunks[i + 1] & 0x07) << 3) | (chunks[i + 2] & 0x07)
            out.append(b)
    return out.decode("utf-8", errors="replace")


def run_shor_rsa(
    N: int = 15,
    e: int = 7,
    a: Optional[int] = None,
    input_mode: str = "number",
    message_value: Optional[int] = 17,
    ciphertext_values: Optional[List[int]] = None,
    text_input: Optional[str] = None,
    chunk_mode: Optional[str] = None,
    shots: int = 4096,
    seed: int = 17,
) -> Dict[str, Any]:
    t0 = time.perf_counter()

    presets = {
        15: {"e": 7, "a": 2, "n_count": 4},
        21: {"e": 5, "a": 2, "n_count": 5},
        33: {"e": 7, "a": 7, "n_count": 5},
        35: {"e": 5, "a": 2, "n_count": 5},
    }
    if N not in presets:
        raise ValueError("Supported toy moduli for statevector simulation are N in {15, 21, 33, 35}.")

    if a is None:
        a = presets[N]["a"]
    if gcd(a, N) != 1:
        raise ValueError(f"Base a={a} must be coprime to N={N}.")

    n_count = presets[N]["n_count"]
    n_target = (N - 1).bit_length()

    # Prepare ciphertext(s) to be attacked (only public N, e, and ciphertext are given to the attacker).
    effective_chunk_mode = chunk_mode
    normalized_message: Optional[int] = None
    target_ciphertexts: List[int] = []

    if input_mode == "text":
        if ciphertext_values:
            target_ciphertexts = [int(c) for c in ciphertext_values]
            if not effective_chunk_mode:
                effective_chunk_mode = "4-bit nibble" if N >= 21 else "3-bit octal"
        else:
            src_text = text_input or "Hi"
            chunks, effective_chunk_mode = _encode_text_chunks(src_text, N)
            target_ciphertexts = [pow(ch, e, N) for ch in chunks]
    else:
        if ciphertext_values:
            target_ciphertexts = [int(ciphertext_values[0]) % N]
        else:
            orig = 17 if message_value is None else int(message_value)
            normalized_message = orig % N
            target_ciphertexts = [pow(normalized_message, e, N)]

    # Build and run Shor's period-finding circuit from Q3_Quantum_Attacks/shor_rsa.py
    circuit = shor_rsa.build_shor_circuit(a, N, n_count=n_count)
    sampler = StatevectorSampler(default_shots=shots, seed=seed)
    counts = sampler.run([circuit]).result()[0].data.c.get_counts()

    candidate_periods: List[int] = []
    phase_observations: List[Dict[str, Any]] = []
    for bits, freq in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        clean_bits = bits.replace(" ", "")
        measured = int(clean_bits, 2)
        phase = measured / (1 << n_count)
        r0 = Fraction(phase).limit_denominator(N).denominator
        verified_r = None
        for mult in range(1, N + 1):
            r = r0 * mult
            if r > 0 and pow(a, r, N) == 1:
                verified_r = r
                if r not in candidate_periods:
                    candidate_periods.append(r)
                break
        if len(phase_observations) < 12:
            phase_observations.append({
                "bits": clean_bits,
                "measured": measured,
                "phase": round(phase, 4),
                "r_estimate": r0,
                "verified_period": verified_r,
                "count": freq,
            })

    factors: List[int] = []
    used_period: Optional[int] = None
    for r in candidate_periods:
        if r % 2 != 0:
            continue
        x = pow(a, r // 2, N)
        if x in (1, N - 1):
            continue
        found_here = []
        for f in (gcd(x - 1, N), gcd(x + 1, N)):
            if 1 < f < N and N % f == 0 and f not in factors:
                factors.append(f)
                found_here.append(f)
        if found_here and used_period is None:
            used_period = r

    factors.sort()
    recovered_p = factors[0] if len(factors) >= 2 else None
    recovered_q = factors[1] if len(factors) >= 2 else None
    recovered_phi: Optional[int] = None
    recovered_d: Optional[int] = None
    decrypted_values: List[int] = []
    recovered_text: Optional[str] = None
    verified = False

    if recovered_p and recovered_q and recovered_p * recovered_q == N:
        recovered_phi = (recovered_p - 1) * (recovered_q - 1)
        if gcd(e, recovered_phi) == 1:
            recovered_d = pow(e, -1, recovered_phi)
            decrypted_values = [pow(c, recovered_d, N) for c in target_ciphertexts]
            if input_mode == "text" and effective_chunk_mode:
                recovered_text = _decode_text_chunks(decrypted_values, effective_chunk_mode)
                verified = True if ciphertext_values else (recovered_text == (text_input or "Hi"))
            else:
                re_encrypted = [pow(m, e, N) for m in decrypted_values]
                verified = re_encrypted == [c % N for c in target_ciphertexts]

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "ok": True,
        "algorithm": "shor_rsa",
        "N": N,
        "e": e,
        "a": a,
        "n_count": n_count,
        "n_target": n_target,
        "n_qubits": circuit.num_qubits,
        "shots": shots,
        "input_mode": input_mode,
        "chunk_mode": effective_chunk_mode,
        "normalized_message": normalized_message,
        "target_ciphertexts": target_ciphertexts,
        "counts": dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True)),
        "phase_observations": phase_observations,
        "candidate_periods": candidate_periods,
        "used_period": used_period,
        "factors": factors,
        "recovered_phi": recovered_phi,
        "recovered_d": recovered_d,
        "decrypted_values": decrypted_values,
        "recovered_text": recovered_text,
        "factorization_check": bool(recovered_p and recovered_q and recovered_p * recovered_q == N),
        "verified": verified,
        "elapsed_ms": elapsed_ms,
    }


def run_shor_ecc(
    target_d: Optional[int] = 3,
    public_point: Optional[List[int]] = None,
    shots: int = 4096,
    seed: int = 29,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    p, a, b, G, points = _ORDER_8_CURVE
    order = 8

    if public_point is not None:
        Q = (int(public_point[0]), int(public_point[1]))
        valid_subgroup = [shor_ecc.ec_mul(k, G, a, p) for k in range(1, order)]
        if Q not in valid_subgroup:
            raise ValueError(f"Public point {Q} is not in the order-8 subgroup generated by G={G}.")
        reference_d = valid_subgroup.index(Q) + 1
    else:
        d_val = 3 if target_d is None else int(target_d)
        if d_val < 1 or d_val >= order:
            raise ValueError("Secret scalar d must be in [1, 7] for the order-8 toy curve.")
        reference_d = d_val
        Q = shor_ecc.ec_mul(reference_d, G, a, p)

    circuit = shor_ecc.build_ecc_circuit(p, a, G, Q, points, order=order)
    sampler = StatevectorSampler(default_shots=shots, seed=seed)
    joint_counts = sampler.run([circuit]).result()[0].data.c.get_counts()

    n_count = (order - 1).bit_length()
    mask = (1 << n_count) - 1
    candidates: Dict[int, int] = {}
    uv_samples: List[Dict[str, Any]] = []

    for bitstring, frequency in sorted(joint_counts.items(), key=lambda kv: kv[1], reverse=True):
        clean_bits = bitstring.replace(" ", "")
        value = int(clean_bits, 2)
        u = value & mask
        v = (value >> n_count) & mask
        d_cand = None
        if u % 2 == 1:
            cand = (v * pow(u, -1, order)) % order
            if shor_ecc.ec_mul(cand, G, a, p) == Q:
                d_cand = cand
                candidates[cand] = candidates.get(cand, 0) + frequency
        uv_samples.append({
            "bitstring": clean_bits,
            "u": u,
            "v": v,
            "u_invertible": (u % 2 == 1),
            "candidate_d": d_cand,
            "count": frequency,
        })

    recovered_d = max(candidates, key=candidates.get) if candidates else None
    verified = recovered_d is not None and shor_ecc.ec_mul(recovered_d, G, a, p) == Q
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "ok": True,
        "algorithm": "shor_ecc",
        "curve": {"p": p, "a": a, "b": b, "G": [G[0], G[1]], "order": order},
        "Q": [Q[0], Q[1]],
        "reference_d": reference_d if public_point is None else None,
        "n_qubits": circuit.num_qubits,
        "shots": shots,
        "joint_counts": dict(sorted(joint_counts.items(), key=lambda kv: kv[1], reverse=True)),
        "uv_samples": uv_samples,
        "candidates": {str(k): v for k, v in candidates.items()},
        "recovered_d": recovered_d,
        "verified": verified,
        "elapsed_ms": elapsed_ms,
    }


def _fit_aes_block(plaintext: str) -> Tuple[bytes, bool]:
    raw = plaintext.encode("utf-8")
    truncated = len(raw) > 16
    if len(raw) >= 16:
        return raw[:16], truncated
    # PKCS#7-like or space padding if shorter than 16 bytes; pad with spaces or PKCS#7
    pad_len = 16 - len(raw)
    return raw + bytes([pad_len] * pad_len), False


def run_grover_aes(
    plaintext: str = "Toy AES demo!!!!",
    secret_k: Optional[int] = 11,
    target_ciphertext_hex: Optional[str] = None,
    n_bits: int = 4,
    shots: int = 4096,
    seed: int = 41,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if n_bits not in (4, 5, 6):
        raise ValueError("n_bits must be 4 (16 keys), 5 (32 keys), or 6 (64 keys).")

    space_size = 1 << n_bits
    raw_pt = plaintext.encode("utf-8")
    if len(raw_pt) == 16:
        block = raw_pt
        padded_note = "exact 16-byte block"
        used_pkcs7 = False
    elif len(raw_pt) < 16:
        pad_len = 16 - len(raw_pt)
        block = raw_pt + bytes([pad_len] * pad_len)
        padded_note = f"PKCS#7 padded from {len(raw_pt)} to 16 bytes"
        used_pkcs7 = True
    else:
        block = raw_pt[:16]
        padded_note = f"truncated from {len(raw_pt)} to first 16-byte block"
        used_pkcs7 = False

    if target_ciphertext_hex:
        cleaned = target_ciphertext_hex.strip().replace(" ", "")
        target_ct = bytes.fromhex(cleaned)
        if len(target_ct) != 16:
            raise ValueError("Target ciphertext must be exactly 16 bytes (32 hex characters).")
    else:
        k_val = 11 if secret_k is None else int(secret_k)
        if k_val < 0 or k_val >= space_size:
            raise ValueError(f"secret_k must be in [0, {space_size - 1}] for n_bits={n_bits}.")
        target_ct = grover_aes.encrypt(grover_aes.candidate_key(k_val), block)

    marked = [
        k for k in range(space_size)
        if grover_aes.encrypt(grover_aes.candidate_key(k), block) == target_ct
    ]

    if not marked:
        raise ValueError(
            f"No key in the {n_bits}-bit restricted family (0..{space_size - 1}) maps the given plaintext block to this ciphertext."
        )

    oracle = grover_aes.phase_oracle(n_bits, marked)
    Q = grover_operator(oracle)
    iterations = max(1, round((math.pi / 4.0) * (space_size / len(marked)) ** 0.5))
    qc = QuantumCircuit(n_bits, n_bits)
    qc.h(range(n_bits))
    for _ in range(iterations):
        qc.compose(Q, inplace=True)
    qc.measure(range(n_bits), range(n_bits))

    counts = StatevectorSampler(default_shots=shots, seed=seed).run([qc]).result()[0].data.c.get_counts()
    sorted_counts = dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
    top_bits = next(iter(sorted_counts))
    recovered_k = int(top_bits.replace(" ", ""), 2)
    recovered_key = grover_aes.candidate_key(recovered_k)
    decrypted_block = AES.new(recovered_key, AES.MODE_ECB).decrypt(target_ct)

    decrypted_text: str
    if used_pkcs7 and decrypted_block == block:
        pad_len = decrypted_block[-1]
        decrypted_text = decrypted_block[:-pad_len].decode("utf-8", errors="replace")
    else:
        decrypted_text = decrypted_block.decode("utf-8", errors="replace")

    verified = (recovered_k in marked) and (decrypted_block == block)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "ok": True,
        "algorithm": "grover_aes",
        "n_bits": n_bits,
        "n_qubits": qc.num_qubits,
        "search_space": space_size,
        "shots": shots,
        "iterations": iterations,
        "plaintext_hex": block.hex(),
        "plaintext_note": padded_note,
        "target_ciphertext_hex": target_ct.hex(),
        "marked_states": marked,
        "counts": sorted_counts,
        "recovered_k": recovered_k,
        "recovered_bits": top_bits.replace(" ", ""),
        "recovered_key_hex": recovered_key.hex(),
        "decrypted_hex": decrypted_block.hex(),
        "decrypted_text": decrypted_text,
        "top_probability_pct": round(sorted_counts[top_bits] * 100.0 / shots, 2),
        "verified": verified,
        "elapsed_ms": elapsed_ms,
    }


def _sha_candidate_message(prefix: str, k: int, suffix_mode: str) -> bytes:
    prefix_bytes = prefix.encode("utf-8")
    if suffix_mode == "decimal_ascii":
        return prefix_bytes + str(k).encode("ascii")
    if suffix_mode == "hex_char":
        return prefix_bytes + format(k, "x").encode("ascii")
    return prefix_bytes + bytes([k])


def run_grover_sha512(
    prefix: str = "toy-preimage-",
    suffix_mode: str = "raw_byte",
    secret_k: Optional[int] = 9,
    target_digest_hex: Optional[str] = None,
    n_bits: int = 4,
    shots: int = 4096,
    seed: int = 53,
    candidates: Optional[List[str]] = None,
) -> Dict[str, Any]:
    t0 = time.perf_counter()
    if n_bits not in (4, 5, 6):
        raise ValueError("n_bits must be 4 (16 candidates), 5 (32 candidates), or 6 (64 candidates).")
    if suffix_mode not in ("raw_byte", "decimal_ascii", "hex_char"):
        raise ValueError("suffix_mode must be raw_byte, decimal_ascii, or hex_char.")
    if suffix_mode == "hex_char" and n_bits > 4:
        raise ValueError("hex_char suffix_mode supports n_bits=4 (0..f).")

    space_size = 1 << n_bits
    if candidates is not None:
        if len(candidates) != space_size:
            raise ValueError(f"Custom candidate list must contain exactly {space_size} strings for {n_bits} qubits.")
        candidate_bytes = [c.encode("utf-8") for c in candidates]
    else:
        candidate_bytes = [_sha_candidate_message(prefix, k, suffix_mode) for k in range(space_size)]

    if target_digest_hex:
        target_digest = target_digest_hex.strip().lower()
        if len(target_digest) != 128:
            raise ValueError("Target SHA-512 digest must be 128 hex characters.")
    else:
        k_val = 9 if secret_k is None else int(secret_k)
        if k_val < 0 or k_val >= space_size:
            raise ValueError(f"secret_k must be in [0, {space_size - 1}] for n_bits={n_bits}.")
        target_msg = candidate_bytes[k_val]
        target_digest = hashlib.sha512(target_msg).hexdigest()

    marked = [
        k for k, msg_bytes in enumerate(candidate_bytes)
        if hashlib.sha512(msg_bytes).hexdigest() == target_digest
    ]

    if not marked:
        raise ValueError(
            "Target digest did not match any candidate in the quantum search space."
        )

    oracle = grover_sha512.phase_oracle(n_bits, marked)
    Q = grover_operator(oracle)
    iterations = max(1, round((math.pi / 4.0) * (space_size / len(marked)) ** 0.5))

    qc = QuantumCircuit(n_bits, n_bits)
    qc.h(range(n_bits))
    for _ in range(iterations):
        qc.compose(Q, inplace=True)
    qc.measure(range(n_bits), range(n_bits))

    counts = StatevectorSampler(default_shots=shots, seed=seed).run([qc]).result()[0].data.c.get_counts()
    sorted_counts = dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
    top_bits = next(iter(sorted_counts))
    recovered_k = int(top_bits.replace(" ", ""), 2)
    recovered_msg_bytes = candidate_bytes[recovered_k]
    recovered_digest = hashlib.sha512(recovered_msg_bytes).hexdigest()

    verified = (recovered_k in marked) and (recovered_digest == target_digest)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "ok": True,
        "algorithm": "grover_sha512",
        "n_bits": n_bits,
        "n_qubits": qc.num_qubits,
        "search_space": space_size,
        "suffix_mode": suffix_mode,
        "prefix": prefix,
        "shots": shots,
        "iterations": iterations,
        "target_digest_hex": target_digest,
        "marked_states": marked,
        "counts": sorted_counts,
        "recovered_k": recovered_k,
        "recovered_bits": top_bits.replace(" ", ""),
        "recovered_message_repr": repr(recovered_msg_bytes),
        "recovered_message_text": recovered_msg_bytes.decode("utf-8", errors="replace"),
        "recovered_message_hex": recovered_msg_bytes.hex(),
        "recovered_digest_hex": recovered_digest,
        "top_probability_pct": round(sorted_counts[top_bits] * 100.0 / shots, 2),
        "verified": verified,
        "elapsed_ms": elapsed_ms,
    }
