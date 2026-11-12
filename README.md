# Cryptography Assignment - Combined Submission

| Folder | Assignment | Language |
|---|---|---|
| `Q1_AES256_RSA/` | AES-256 and RSA crypto system | C++17 |
| `Q2_ECC_SHA512/` | ECC (NIST P-256) and SHA-512 | C++11 |
| `Q3_Quantum_Attacks/` | Shor's and Grover's algorithms against RSA, ECC, AES-128, SHA-512 | Python (Qiskit) |
| `ui/` | Interactive Web Workbench (FastAPI + C++ bridge + React/Vite) | Python / TS |

Each folder has its own README with build / run instructions. The full report is `Assignment_Report.docx`.

## Web UI Workbench (`ui/`)

An interactive web workbench wraps the original Q1/Q2 C++ engines and Q3 Qiskit quantum attack scripts without modifying any original assignment files:

- **Encrypt & Hash:** Input a plain message, pick `AES-256 Lock`, `RSA Key Lock`, `SHA-512 Hash`, `Digital Signature (ECDSA)`, or `Shared Secret (ECDH)`, and immediately encrypt, sign, verify, or round-trip decrypt (with advanced cryptographic details neatly expandable).
- **Quantum Attack:** Provide an encrypted output, SHA-512 fingerprint, or ECC public point (or send directly from Encrypt & Hash) and watch `Shor` (`RSA`, `ECC`) or `Grover` (`AES-128`, `SHA-512`) recover the original secret via Qiskit `StatevectorSampler`.
- **Lab Tests:** Open the `Lab Tests` drawer from the top-right header to run all original Q1, Q2 (18 checks + speed benchmarks), and Q3 verification suites.

### Prerequisites
- `g++` (with C++11 and C++17 support) and `make`
- `python3` (3.10+) with `pip` and `venv`
- `node` (18+) and `npm`

### One-Command Start (Recommended)
After cloning the repository, run from the project root:
```bash
git clone <your-repo-url>
cd Crypto_Assignment
./ui/start.sh
```
This automatically:
1. Compiles the C++ bridge binaries (`ui/backend/cpp_bridge/bin/`)
2. Creates `ui/backend/.venv` and installs Python dependencies from `requirements.txt` / `ui/backend/requirements.txt`
3. Installs frontend packages and builds the React bundle (`ui/frontend/dist/`)
4. Starts the web app at **http://127.0.0.1:8000**

Useful flags:
- `./ui/start.sh --rebuild` — force-rebuild both the C++ bridge binaries and the frontend production bundle.
- `./ui/start.sh --dev` — run FastAPI with `--reload` on `http://127.0.0.1:8000` alongside Vite hot-reload dev server on `http://127.0.0.1:5173`.

### Manual Setup & Run (Step by Step)
```bash
# 1. Build C++ bridge binaries
make -C ui/backend/cpp_bridge

# 2. Build the React frontend bundle
cd ui/frontend
npm install
npm run build
cd ../..

# 3. Create Python virtual environment, install requirements, and start the server
python3 -m venv ui/backend/.venv
ui/backend/.venv/bin/pip install -r requirements.txt
cd ui/backend
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```
Then open **http://127.0.0.1:8000** in your browser.

*(For frontend hot-reload during development, run `npm run dev` inside `ui/frontend/` in a second terminal and open **http://127.0.0.1:5173**.)*

## Quick start (CLI Assignments)
```
# Q1
cd Q1_AES256_RSA
g++ -std=c++17 -O2 AES256.cpp -o aes256 && ./aes256
g++ -std=c++17 -O2 RSA.cpp -o rsa_demo && ./rsa_demo

# Q2
cd ../Q2_ECC_SHA512 && make && ./ecc_sha512

# Q3
cd ../Q3_Quantum_Attacks && pip install -r requirements.txt && python shor_rsa.py
```
