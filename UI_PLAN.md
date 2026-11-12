# Cryptography & Quantum Attack Lab — UI Architecture & Implementation Plan

> **Status:** Draft for Review (No application code written yet)  
> **Workspace:** `/home/kunal/Desktop/Crypto/Crypto_Assignment`  
> **Installed Design Skills:** `.agents/skills/design-taste-frontend` (Taste Skill v2.5.1) & `.agents/skills/impeccable` (Impeccable v4.8.2)

---

## 1. Codebase & Report Audit Summary

This UI wraps the three assignment modules directly so the interface executes the **actual C++ and Python/Qiskit implementations** rather than re-implementing approximations in JavaScript:

| Module | Source Files | Core Capabilities | Constraints / Guardrails Observed |
| :--- | :--- | :--- | :--- |
| **Q1 Part A: AES-256** | `Q1_AES256_RSA/AES256.cpp` (C++17) | `keyExpansion` (60 words / 15 round keys), `encryptState`, `decryptState`, 14 rounds, compile-time `INV_SBOX`, GF($2^8$) `mixColumns`/`invMixColumns` | Currently operates on a single 16-byte block with hardcoded NIST test vector in `main()`. Arbitrary strings require PKCS#7 multi-block framing in a wrapper. |
| **Q1 Part B: RSA** | `Q1_AES256_RSA/RSA.cpp` (C++17) | `generateDemoKeys(p, q, e)`, `encryptNumber`, `decryptNumber`, `encryptText` (per-ASCII-byte), `decryptText`, `modPow`, `extendedGCD` | Uses `long long` (`int64`) with demo primes `p = 1009, q = 1013, e = 65537` (`n = 1,022,117`, `d = 832,193`). Byte-by-byte textbook RSA is deterministic. |
| **Q2 Part A: SHA-512** | `Q2_ECC_SHA512/sha512.h`, `sha512.cpp`, `main.cpp` (C++11) | Streaming & one-shot FIPS 180-4 SHA-512 (`pad -> 128B blocks -> 80 rounds -> 512-bit hex`); CLI already supports `./ecc_sha512 hash "text"` | Produces 128 hex characters (64 bytes). `main.cpp` also includes NIST KATs, 1-bit avalanche comparison, and throughput benchmarks. |
| **Q2 Part B–D: ECC (NIST P-256)** | `Q2_ECC_SHA512/ecc.h`, `ecc.cpp`, `bigint256.h`, `bigint256.cpp` (C++11) | Custom 256-bit `U256` limb arithmetic, Jacobian point `add`/`dbl`/`scalarMul`, `randomScalar`, `ecdh`, `sign`/`verify` (using SHA-512) | Uses official NIST P-256 curve constants; non-constant-time double-and-add (learning code). |
| **Q3: Shor & Grover** | `Q3_Quantum_Attacks/shor_rsa.py`, `shor_ecc.py`, `grover_aes.py`, `grover_sha512.py` (Python + Qiskit) | `StatevectorSampler` circuits for: Shor period-finding on RSA (`N=15`), Shor Fourier sampling on toy ECC (`GF(17)`, order `8`), Grover 4-bit AES-128 key search, Grover 4-bit SHA-512 pre-image search | Classical statevector simulation limits qubit count (~8–11 qubits). Grover oracles are classically compiled lookup circuits over restricted $2^n$ spaces (`n=4` default). |

---

## 2. Core User Flow: Forward (Classical) vs. Reverse (Quantum Attack)

The UI is structured around two mirrored workflows plus a verification/benchmark view:

### A. Classical Mode — Forward Direction (`String Input -> Algorithm -> Cryptographic Output`)
The user enters a plaintext/message string, selects an algorithm, configures or auto-generates keys/parameters, and generates the cryptographic value (with optional round-trip decryption/verification):

1. **AES-256 (`AES256.cpp` core)**
   - **Input:** Plaintext string (UTF-8) + 256-bit key (64 hex chars, passphrase-derived via SHA-512, random generator, or NIST FIPS-197 preset `0001...1F`).
   - **Process:** PKCS#7-pad input into 16-byte blocks -> run `keyExpansion()` + `encryptState()` per block via the C++ bridge.
   - **Output:** Ciphertext (Hex), block count, first-block $4 \times 4$ `State` matrix preview, and one-click **Decrypt** back to the original string.
2. **RSA (`RSA.cpp` core)**
   - **Input:** Plaintext string (ASCII) or integer $0 \le M < n$, plus primes $(p, q)$ and public exponent $e$ (defaults: `p=1009, q=1013, e=65537`; validated with `isPrime` and `gcd(e, phi) == 1`).
   - **Process:** Run `generateDemoKeys()` and `encryptText()` / `encryptNumber()`.
   - **Output:** Keypair $(n, \phi(n), e, d)$, space-separated ciphertext integers, per-character mapping table (`char -> ASCII -> M^e mod n`, visually highlighting repeated-character determinism from the report), and **Decrypt** back to the original text.
3. **SHA-512 (`sha512.cpp` core)**
   - **Input:** Arbitrary string (or NIST KAT presets: `""`, `"abc"`, 112-byte two-block message).
   - **Process:** Run `SHA512::hash(text)`.
   - **Output:** 128-character hex digest, FIPS 180-4 padding breakdown (`message | 0x80 | zero padding | 128-bit bit-length`), and an **Avalanche Check** toggle (flips 1 bit of the first character and shows bits flipped / 512 vs. 50% ideal).
4. **ECC NIST P-256 — ECDSA & ECDH (`ecc.cpp` + `bigint256.cpp` core)**
   - **ECDSA Mode:**
     - **Input:** Message string + private key $d$ (or "Generate Keypair" via `randomScalar()`).
     - **Output:** Public point $Q = (Q_x, Q_y)$, SHA-512 truncated scalar $e$, signature pair $(r, s)$, and live **Verify / Tamper Test** (edit message, $r$, $s$, or switch to Bob's public key to observe `ACCEPTED` vs. `REJECTED`).
   - **ECDH Mode:**
     - **Input:** Optional Alice/Bob private keys (or generate both) + optional message string.
     - **Output:** $Q_A$, $Q_B$, shared secret $S = d_A Q_B = d_B Q_A$, derived 256-bit symmetric key (`SHA-512(S)[0..63]`), and optional chained AES-256 encryption of the user's message.

### B. Quantum Attack Mode — Reverse Direction (`Cryptographic Output -> Quantum Attack -> Recovered Secret / Plaintext`)
The user starts from a **target cryptographic output** (either pasted manually or sent directly from a Classical/Toy preset via a **"Send to Quantum Attack →"** bridge action), selects the matching quantum attack, and runs the Qiskit `StatevectorSampler` simulation to recover the hidden key/factors/pre-image/plaintext:

1. **Shor's Algorithm vs. RSA (`shor_rsa.py`)**
   - **Reverse Input:** RSA Public Key $(N, e)$ + Target Ciphertext $C$ (supports toy semiprimes feasible for statevector simulation: default $N=15$ (`3×5`), plus selectable $N \in \{15, 21, 33, 35\}$, base $a$ coprime to $N$, and optional short nibble/value-encoded ciphertext blocks).
   - **Quantum Execution:** Builds controlled modular-multiplication QPE + inverse QFT circuit; runs `StatevectorSampler`.
   - **Reverse Output:** Measurement phase distribution chart, continued-fraction candidate periods $r$, recovered prime factors $(p, q)$, reconstructed private exponent $d = e^{-1} \bmod \phi(N)$, **decrypted plaintext**, and `PASS`/`FAIL` verification.
2. **Shor's Algorithm vs. ECC (`shor_ecc.py`)**
   - **Reverse Input:** Toy curve $y^2 \equiv x^3 + x + 2 \pmod{17}$, base point $G=(4, 6)$ of order $8$, and **Target Public Key $Q$** (user selects any valid curve point $Q$ on the curve or sets a target scalar $d \in [1, 7]$ whose $Q = d \cdot G$ is passed to the attacker *without* revealing $d$).
   - **Quantum Execution:** 11-qubit Fourier-sampling circuit computing $f(u, v) = uG + vQ$ + inverse QFT.
   - **Reverse Output:** Joint $(u, v)$ measurement counts, linear congruence solver ($v \equiv d \cdot u \pmod 8$), **recovered private scalar $d$**, and public-key check $d \cdot G == Q$.
3. **Grover's Algorithm vs. AES-128 (`grover_aes.py`)**
   - **Reverse Input:** **Target Ciphertext (hex)** + **Known 16-byte Plaintext** (e.g. user enters any string up to 16 bytes — PKCS#7/zero-padded — and either enters a ciphertext or picks a restricted $n$-bit key ID $k \in [0, 2^n - 1]$ with $n \in \{4, 5, 6\}$ to produce the target ciphertext for the attacker).
   - **Quantum Execution:** Builds $n$-qubit phase oracle + `grover_operator` for $\lfloor \frac{\pi}{4}\sqrt{2^n} \rceil$ iterations.
   - **Reverse Output:** Shot distribution bar chart showing amplitude amplification (~96% on target state), **recovered 128-bit AES key (hex)**, **decrypted plaintext string**, and verification `PASS`/`FAIL`.
4. **Grover's Algorithm vs. SHA-512 (`grover_sha512.py`)**
   - **Reverse Input:** **Target SHA-512 Digest (128 hex chars)** + candidate prefix template (default `"toy-preimage-"` + $n$-bit suffix byte $0 \dots 2^n-1$, customizable prefix string so the user can hash `"my-prefix-" + byte(k)` in Forward SHA-512 or directly here, then reverse the digest with Grover!).
   - **Quantum Execution:** Runs Grover amplitude amplification over the $2^n$ search space ($n \in \{4, 5, 6\}$ qubits).
   - **Reverse Output:** Measurement counts chart, **recovered candidate ID**, **recovered pre-image string**, and digest equality check (`recovered_digest == target_digest`).

> **Scope Transparency:** Every Quantum Attack view displays a clear technical badge noting the qubit count and search-space constraint (e.g., *"4-qubit statevector simulation over restricted 16-key space; real AES-128 requires $2^{64}$ Grover steps and full quantum AES gates"*), matching the assignment report's findings table.

### C. Suite Tests & Benchmarks Mode (Verification Hub)
- One-click runner for the assignment's built-in verification tests (`Q1 AES256 KAT`, `Q1 RSA Demo`, `Q2 18/18 ECC+SHA-512 Tests`, `Q2 Throughput & Latency Benchmarks`) plus the **Post-Quantum Security Summary Table** (RSA, ECC P-256, AES-128, AES-256, SHA-512).

---

## 3. Technical Architecture

### Why Backend Execution + React Frontend?
Running the actual C++17/C++11 code and Qiskit Python scripts behind a lightweight local API guarantees 100% fidelity with the assignment submission while giving the browser a responsive, modern interface.

```
Crypto_Assignment/
├── Q1_AES256_RSA/          # Untouched original assignment files
├── Q2_ECC_SHA512/          # Untouched original assignment files
├── Q3_Quantum_Attacks/     # Untouched original assignment files
└── ui/
    ├── backend/
    │   ├── cpp_bridge/
    │   │   ├── aes256_cli.cpp   # Wraps AES256.cpp (compiles with -Dmain=orig_main) + PKCS#7 multi-block JSON CLI
    │   │   ├── rsa_cli.cpp      # Wraps RSA.cpp (compiles with -Dmain=orig_main) + JSON CLI
    │   │   ├── ecc_sha_cli.cpp  # Links directly against Q2 sha512.cpp, ecc.cpp, bigint256.cpp + JSON CLI
    │   │   └── Makefile         # Builds the 3 bridge binaries into cpp_bridge/bin/
    │   ├── quantum_service.py   # Imports/wraps Q3 shor_rsa, shor_ecc, grover_aes, grover_sha512 with custom inputs
    │   ├── app.py               # FastAPI server + static file serving for production build
    │   ├── requirements.txt     # fastapi, uvicorn, pydantic, qiskit>=1.0, numpy, pycryptodome
    │   └── .venv/               # Isolated Python virtual environment
    ├── frontend/                # React 19 + TypeScript + Vite + Tailwind CSS
    │   ├── PRODUCT.md           # Created via /impeccable init during implementation
    │   ├── DESIGN.md            # Design system tokens & rules
    │   └── src/
    │       ├── components/      # ModeSwitcher, AlgorithmSelector, HexInspector, ShotChart, StateMatrix, etc.
    │       ├── views/           # ClassicalLab, QuantumAttackLab, TestBenchView
    │       └── api/             # Typed fetch client for FastAPI endpoints
    └── start.sh                 # Builds C++ bridge if needed, activates .venv, starts backend (+ Vite in dev)
```

### Non-Invasive C++ Wrapping Strategy
- **Zero edits to `Q1_AES256_RSA/` or `Q2_ECC_SHA512/`**:
  - `Q2` already separates headers (`sha512.h`, `ecc.h`, `bigint256.h`) from `main.cpp`, so `ecc_sha_cli.cpp` compiles directly against `../../Q2_ECC_SHA512/{sha512,ecc,bigint256}.cpp`.
  - `AES256.cpp` and `RSA.cpp` define `int main()`, so `aes256_cli.cpp` and `rsa_cli.cpp` include them with `#define main assignment_main` before `#include` (and `#undef main` after) — exposing `keyExpansion`, `encryptState`, `decryptState`, `generateDemoKeys`, `encryptText`, `decryptText` directly with zero duplication or divergence.

---

## 4. API Endpoint Specification

| Method & Path | Purpose | Key Request Fields | Key Response Fields |
| :--- | :--- | :--- | :--- |
| `GET /api/health` | Verify C++ binaries & Qiskit runtime | — | `cpp_ready`, `qiskit_version`, `binaries` |
| `POST /api/classical/aes256` | AES-256 encrypt or decrypt | `action` (`encrypt`\|`decrypt`), `input`, `key_hex` or `passphrase`, `mode` (`pkcs7`\|`single_block`) | `output_hex` / `recovered_text`, `key_hex`, `blocks`, `first_state_matrix`, `elapsed_ms` |
| `POST /api/classical/rsa` | RSA keygen + encrypt or decrypt | `action` (`encrypt`\|`decrypt`), `input`, `input_type` (`text`\|`number`), `p`, `q`, `e` | `keys` (`n, phi, e, d`), `ciphertext_ints` / `recovered_text`, `char_breakdown`, `elapsed_ms` |
| `POST /api/classical/sha512` | SHA-512 hash + optional 1-bit avalanche | `text`, `avalanche_check` (bool) | `digest_hex`, `padding_summary`, `avalanche` (`modified_text`, `diff_bits`, `diff_pct`), `elapsed_ms` |
| `POST /api/classical/ecc/ecdsa` | P-256 keygen, ECDSA sign, or verify | `action` (`keygen`\|`sign`\|`verify`), `message`, `priv_hex`, `pub_x`, `pub_y`, `r`, `s` | `priv_hex`, `pub` (`x, y`), `digest_e`, `signature` (`r, s`), `valid` (bool) |
| `POST /api/classical/ecc/ecdh` | P-256 ECDH shared secret & key | `alice_priv_hex`, `bob_priv_hex`, `optional_message` | `alice_pub`, `bob_pub`, `shared_secret`, `derived_aes_key`, `matched` (bool) |
| `POST /api/quantum/shor-rsa` | Shor attack on toy RSA | `N` (`15\|21\|33\|35`), `e`, `a`, `message_or_ciphertext`, `is_ciphertext`, `shots` | `n_qubits`, `counts`, `periods`, `factors`, `recovered_d`, `decrypted`, `verified`, `elapsed_ms` |
| `POST /api/quantum/shor-ecc` | Shor Fourier sampling on toy ECC | `target_d` or `Q` (`[x, y]`), `shots` | `curve` (`p, a, b, G, order`), `Q`, `n_qubits`, `joint_counts`, `candidates`, `recovered_d`, `verified` |
| `POST /api/quantum/grover-aes` | Grover key search on toy AES-128 | `plaintext`, `secret_k` or `target_ciphertext_hex`, `n_bits` (`4\|5\|6`), `shots` | `target_ciphertext_hex`, `marked`, `iterations`, `counts`, `recovered_k`, `recovered_key_hex`, `decrypted_text`, `verified` |
| `POST /api/quantum/grover-sha512` | Grover pre-image search on SHA-512 | `prefix`, `secret_k` or `target_digest_hex`, `n_bits` (`4\|5\|6`), `shots` | `target_digest_hex`, `marked`, `iterations`, `counts`, `recovered_k`, `recovered_message`, `verified` |
| `POST /api/tests/run` | Run original Q1/Q2/Q3 checks & bench | `suite` (`all`\|`q1`\|`q2`\|`q3`\|`bench`) | Parsed test rows (`name`, `status`, `detail`) + benchmark metrics |

---

## 5. UI Layout & Design Direction (Using Taste Skill & Impeccable)

When we move to implementation, we will follow the installed **`impeccable`** (`new-work` + `craft-floor.md`) and **`design-taste-frontend`** guidelines:

1. **Aesthetic Concept — "Cryptographic Bench Instrument"**:
   - Crisp, high-contrast engineering instrument aesthetic (inspired by hardware analyzers / scientific notebooks rather than generic SaaS dashboards or purple-gradient "AI slop").
   - Strict monospace typography (`JetBrains Mono` / `IBM Plex Mono`) for hex digests, 256-bit coordinates, state matrices, and bitstrings paired with a clean geometric sans (`Space Grotesk` or `Plus Jakarta Sans`) for controls and labels.
   - Surface hierarchy with hairline borders (`1px`), zero nested card-in-card clutter, clear primary/secondary action contrast, and responsive 2-column workbench layout (Input & Parameters on the left, Generated Output & Quantum/Math Telemetry on the right) collapsing cleanly on smaller viewports.
2. **Interactive Highlights**:
   - **Symmetric Mode Switcher**: Prominent **Classical (Forward)** vs. **Quantum Attack (Reverse)** toggle in the top bar that visibly flips the data-flow direction (`Plaintext → Value` vs. `Value → Recovered Secret`).
   - **Live Handoff Bridge**: A `"Reverse with Quantum Attack →"` action on compatible Classical outputs (e.g., SHA-512 pre-image prefix digest, toy RSA ciphertext, toy AES-128 ciphertext) that transitions directly into Quantum Attack Mode pre-populated with that target value.
   - **Data-Driven Visualizations (SVG / Canvas, zero bloat)**:
     - Interactive $4 \times 4$ AES State Matrix byte grid.
     - Qiskit Measurement Probability Histogram (highlighting period peaks in Shor and ~96% amplified target state in Grover).
     - SHA-512 1-bit Avalanche Diff visualizer showing changed hex nibbles/bits.
3. **Quality Gates Before Sign-Off**:
   - Run `impeccable` detector/audit (`scripts/impeccable detect` / `audit`) and `design-taste-frontend` browser checks across desktop & mobile widths to verify contrast, spacing, alignment, and zero console errors.

---

## 6. Phased Execution Plan (For Next Steps After Approval)

1. **Phase 1 — Runtime & C++ Bridge Setup**
   - Build `ui/backend/cpp_bridge/` (`aes256_cli`, `rsa_cli`, `ecc_sha_cli`) and verify outputs match `TEST_RESULTS_AES256.txt`, `TEST_RESULTS_RSA.txt`, and `Q2_ECC_SHA512/docs/output.txt`.
   - Create `ui/backend/.venv` and install `qiskit>=1.0`, `numpy`, `pycryptodome`, `fastapi`, `uvicorn`.
2. **Phase 2 — FastAPI Backend & Quantum Service**
   - Implement `quantum_service.py` and `app.py` wrapping all 4 Q3 scripts + C++ bridge calls + test runner.
   - Smoke-test every `/api/*` endpoint via `curl` / `pytest`.
3. **Phase 3 — Frontend Workbench Implementation**
   - Scaffold Vite + React + TypeScript + Tailwind in `ui/frontend/`.
   - Run `impeccable` context/craft-floor workflow and `design-taste-frontend` layout rules to build the Classical Lab, Quantum Attack Lab, and Test/Benchmark Suite views.
4. **Phase 4 — End-to-End & Visual Verification**
   - Verify all 4 forward classical algorithms (string in -> value out -> round-trip decrypt/verify).
   - Verify all 4 reverse quantum attacks (target value in -> Qiskit simulation -> secret/plaintext recovered).
   - Run `impeccable` / browser checks and finalize `ui/start.sh` + documentation.
