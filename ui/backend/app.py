import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import qiskit
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import quantum_service

BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parents[1]
BIN_DIR = BACKEND_DIR / "cpp_bridge" / "bin"
FRONTEND_DIST = BACKEND_DIR.parent / "frontend" / "dist"

app = FastAPI(
    title="Cryptography & Quantum Attack Lab API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _run_cpp_json(binary_name: str, args: List[str]) -> Dict[str, Any]:
    binary = BIN_DIR / binary_name
    if not binary.exists():
        raise HTTPException(
            status_code=500,
            detail=f"C++ bridge binary '{binary_name}' not found. Run 'make' in ui/backend/cpp_bridge.",
        )
    t0 = time.perf_counter()
    proc = subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    stdout = proc.stdout.strip()
    if not stdout:
        raise HTTPException(status_code=500, detail=proc.stderr.strip() or f"{binary_name} returned empty output.")
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Invalid JSON from {binary_name}: {exc}") from exc

    if not payload.get("ok"):
        raise HTTPException(status_code=400, detail=payload.get("error", "C++ execution error"))

    payload["elapsed_ms"] = elapsed_ms
    return payload


def _text_to_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def _hex_to_text(hex_str: str) -> str:
    return bytes.fromhex(hex_str).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------


class AES256Request(BaseModel):
    action: Literal["encrypt", "decrypt"] = "encrypt"
    input_data: str = ""
    input_encoding: Literal["utf8", "hex"] = "utf8"
    key_hex: Optional[str] = None
    passphrase: Optional[str] = None
    padding: Literal["pkcs7", "none"] = "pkcs7"


class RSARequest(BaseModel):
    action: Literal["encrypt", "decrypt"] = "encrypt"
    input_type: Literal["text", "number"] = "text"
    input_data: str = "Hello RSA!"
    p: int = 1009
    q: int = 1013
    e: int = 65537


class SHA512Request(BaseModel):
    text: str = "abc"
    avalanche_check: bool = True


class ECDSARequest(BaseModel):
    action: Literal["keygen", "sign", "verify"] = "sign"
    message: str = "Transfer Rs. 5000 to account 1234567890"
    priv_hex: Optional[str] = "auto"
    pub_x: Optional[str] = None
    pub_y: Optional[str] = None
    r: Optional[str] = None
    s: Optional[str] = None


class ECDHRequest(BaseModel):
    alice_priv_hex: Optional[str] = "auto"
    bob_priv_hex: Optional[str] = "auto"
    optional_message: Optional[str] = None


class ShorRSARequest(BaseModel):
    N: int = 15
    e: int = 7
    a: Optional[int] = None
    input_mode: Literal["number", "text"] = "number"
    message_value: Optional[int] = 17
    ciphertext_values: Optional[List[int]] = None
    text_input: Optional[str] = None
    chunk_mode: Optional[str] = None
    shots: int = Field(default=4096, ge=128, le=16384)
    seed: int = 17


class ShorECCRequest(BaseModel):
    target_d: Optional[int] = 3
    public_point: Optional[List[int]] = None
    shots: int = Field(default=4096, ge=128, le=16384)
    seed: int = 29


class GroverAESRequest(BaseModel):
    plaintext: str = "Toy AES demo!!!!"
    secret_k: Optional[int] = 11
    target_ciphertext_hex: Optional[str] = None
    n_bits: int = Field(default=4, ge=4, le=6)
    shots: int = Field(default=4096, ge=128, le=16384)
    seed: int = 41


class GroverSHA512Request(BaseModel):
    prefix: str = "toy-preimage-"
    suffix_mode: Literal["raw_byte", "decimal_ascii", "hex_char"] = "raw_byte"
    secret_k: Optional[int] = 9
    target_digest_hex: Optional[str] = None
    n_bits: int = Field(default=4, ge=4, le=6)
    shots: int = Field(default=4096, ge=128, le=16384)
    seed: int = 53
    candidates: Optional[List[str]] = None


class RunTestsRequest(BaseModel):
    suite: Literal["all", "q1", "q2", "q3", "bench"] = "all"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/health")
def health() -> Dict[str, Any]:
    bins = {
        name: (BIN_DIR / name).exists()
        for name in ("aes256_cli", "rsa_cli", "ecc_sha_cli", "q2_runner")
    }
    return {
        "ok": True,
        "cpp_ready": all(bins.values()),
        "binaries": bins,
        "qiskit_version": qiskit.__version__,
        "toy_ecc": quantum_service.get_toy_ecc_info(),
    }


@app.post("/api/classical/aes256")
def classical_aes256(req: AES256Request) -> Dict[str, Any]:
    if req.passphrase is not None and req.passphrase != "":
        sha_res = _run_cpp_json("ecc_sha_cli", ["sha512", _text_to_hex(req.passphrase), "0"])
        key_hex = sha_res["digest_hex"][:64].upper()
        key_source = "sha512(passphrase)[0..255]"
    elif req.key_hex:
        key_hex = req.key_hex.strip().replace(" ", "").upper()
        key_source = "hex"
    else:
        raise HTTPException(status_code=400, detail="Provide either a 64-char hex key or a passphrase.")

    if req.action == "encrypt":
        data_hex = (
            req.input_data.strip().replace(" ", "")
            if req.input_encoding == "hex"
            else _text_to_hex(req.input_data)
        )
        res = _run_cpp_json("aes256_cli", ["encrypt", key_hex, data_hex, req.padding])
        res["key_hex"] = key_hex
        res["key_source"] = key_source
        return res

    # Decrypt expects hex ciphertext
    ct_hex = req.input_data.strip().replace(" ", "")
    res = _run_cpp_json("aes256_cli", ["decrypt", key_hex, ct_hex, req.padding])
    res["key_hex"] = key_hex
    res["key_source"] = key_source
    res["recovered_text"] = _hex_to_text(res["output_hex"])
    return res


@app.post("/api/classical/rsa")
def classical_rsa(req: RSARequest) -> Dict[str, Any]:
    if req.input_type == "number":
        cmd = "encrypt_number" if req.action == "encrypt" else "decrypt_number"
        try:
            num = int(req.input_data.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Numeric RSA mode requires an integer.") from exc
        return _run_cpp_json("rsa_cli", [cmd, str(req.p), str(req.q), str(req.e), str(num)])

    if req.action == "encrypt":
        res = _run_cpp_json(
            "rsa_cli",
            ["encrypt_text", str(req.p), str(req.q), str(req.e), _text_to_hex(req.input_data)],
        )
        for item in res.get("breakdown", []):
            byte_val = item["byte"]
            item["char"] = chr(byte_val) if 32 <= byte_val <= 126 else f"0x{byte_val:02x}"
        res["ciphertext_str"] = " ".join(str(x) for x in res["ciphertext_ints"])
        return res

    res = _run_cpp_json(
        "rsa_cli",
        ["decrypt_text", str(req.p), str(req.q), str(req.e), req.input_data.strip()],
    )
    res["recovered_text"] = _hex_to_text(res["recovered_hex"])
    return res


@app.post("/api/classical/sha512")
def classical_sha512(req: SHA512Request) -> Dict[str, Any]:
    res = _run_cpp_json(
        "ecc_sha_cli",
        ["sha512", _text_to_hex(req.text), "1" if req.avalanche_check else "0"],
    )
    if "avalanche" in res:
        av = res["avalanche"]
        av["modified_text"] = _hex_to_text(av["modified_hex"])
        av["diff_pct"] = round(av["diff_bits"] * 100.0 / 512.0, 1)
    return res


@app.post("/api/classical/ecc/ecdsa")
def classical_ecc_ecdsa(req: ECDSARequest) -> Dict[str, Any]:
    if req.action == "keygen":
        return _run_cpp_json("ecc_sha_cli", ["ecc_keygen"])

    if req.action == "sign":
        priv_arg = (req.priv_hex or "auto").strip() or "auto"
        return _run_cpp_json("ecc_sha_cli", ["ecdsa_sign", priv_arg, _text_to_hex(req.message)])

    if not all([req.pub_x, req.pub_y, req.r, req.s]):
        raise HTTPException(status_code=400, detail="Verification requires pub_x, pub_y, r, and s hex values.")
    return _run_cpp_json(
        "ecc_sha_cli",
        [
            "ecdsa_verify",
            req.pub_x.strip(),
            req.pub_y.strip(),
            _text_to_hex(req.message),
            req.r.strip(),
            req.s.strip(),
        ],
    )


@app.post("/api/classical/ecc/ecdh")
def classical_ecc_ecdh(req: ECDHRequest) -> Dict[str, Any]:
    a_priv = (req.alice_priv_hex or "auto").strip() or "auto"
    b_priv = (req.bob_priv_hex or "auto").strip() or "auto"
    res = _run_cpp_json("ecc_sha_cli", ["ecdh", a_priv, b_priv])

    if req.optional_message is not None and req.optional_message != "":
        aes_res = _run_cpp_json(
            "aes256_cli",
            ["encrypt", res["derived_aes_key"].upper(), _text_to_hex(req.optional_message), "pkcs7"],
        )
        res["encrypted_message_hex"] = aes_res["output_hex"]
    return res


@app.post("/api/quantum/shor-rsa")
def quantum_shor_rsa(req: ShorRSARequest) -> Dict[str, Any]:
    try:
        return quantum_service.run_shor_rsa(
            N=req.N,
            e=req.e,
            a=req.a,
            input_mode=req.input_mode,
            message_value=req.message_value,
            ciphertext_values=req.ciphertext_values,
            text_input=req.text_input,
            chunk_mode=req.chunk_mode,
            shots=req.shots,
            seed=req.seed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/quantum/shor-ecc")
def quantum_shor_ecc(req: ShorECCRequest) -> Dict[str, Any]:
    try:
        return quantum_service.run_shor_ecc(
            target_d=req.target_d,
            public_point=req.public_point,
            shots=req.shots,
            seed=req.seed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/quantum/grover-aes")
def quantum_grover_aes(req: GroverAESRequest) -> Dict[str, Any]:
    try:
        return quantum_service.run_grover_aes(
            plaintext=req.plaintext,
            secret_k=req.secret_k,
            target_ciphertext_hex=req.target_ciphertext_hex,
            n_bits=req.n_bits,
            shots=req.shots,
            seed=req.seed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/quantum/grover-sha512")
def quantum_grover_sha512(req: GroverSHA512Request) -> Dict[str, Any]:
    try:
        return quantum_service.run_grover_sha512(
            prefix=req.prefix,
            suffix_mode=req.suffix_mode,
            secret_k=req.secret_k,
            target_digest_hex=req.target_digest_hex,
            n_bits=req.n_bits,
            shots=req.shots,
            seed=req.seed,
            candidates=req.candidates,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/tests/run")
def run_assignment_tests(req: RunTestsRequest) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []

    if req.suite in ("all", "q1"):
        t0 = time.perf_counter()
        aes_proc = subprocess.run([str(BIN_DIR / "aes256_cli"), "kat"], capture_output=True, text=True, timeout=20)
        results.append({
            "id": "q1_aes256",
            "title": "Q1 · AES-256 NIST FIPS-197 Known-Answer Test",
            "language": "C++17",
            "passed": aes_proc.returncode == 0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "output": aes_proc.stdout.strip(),
        })

        t0 = time.perf_counter()
        rsa_proc = subprocess.run([str(BIN_DIR / "rsa_cli"), "kat"], capture_output=True, text=True, timeout=20)
        results.append({
            "id": "q1_rsa",
            "title": "Q1 · RSA Keygen, Numeric & Text Round-Trip",
            "language": "C++17",
            "passed": rsa_proc.returncode == 0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "output": rsa_proc.stdout.strip(),
        })

    if req.suite in ("all", "q2"):
        t0 = time.perf_counter()
        q2_proc = subprocess.run([str(BIN_DIR / "q2_runner")], capture_output=True, text=True, timeout=45)
        results.append({
            "id": "q2_ecc_sha512",
            "title": "Q2 · SHA-512 NIST KATs + ECC P-256 (18 Checks)",
            "language": "C++11",
            "passed": q2_proc.returncode == 0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "output": q2_proc.stdout.strip(),
        })

    if req.suite == "bench":
        t0 = time.perf_counter()
        bench_proc = subprocess.run([str(BIN_DIR / "q2_runner"), "bench"], capture_output=True, text=True, timeout=60)
        results.append({
            "id": "q2_bench",
            "title": "Q2 · SHA-512 Throughput & ECC P-256 Timing Benchmarks",
            "language": "C++11",
            "passed": bench_proc.returncode == 0,
            "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
            "output": bench_proc.stdout.strip(),
        })

    if req.suite in ("all", "q3"):
        q3_scripts = [
            ("q3_shor_rsa", "Q3 · Shor's Algorithm vs Toy RSA (N=15)", "shor_rsa.py"),
            ("q3_shor_ecc", "Q3 · Shor Fourier Sampling vs Toy ECC (Order 8)", "shor_ecc.py"),
            ("q3_grover_aes", "Q3 · Grover Key Search vs Toy AES-128", "grover_aes.py"),
            ("q3_grover_sha512", "Q3 · Grover Pre-Image Search vs SHA-512", "grover_sha512.py"),
        ]
        venv_py = BACKEND_DIR / ".venv" / "bin" / "python"
        py_exec = str(venv_py) if venv_py.exists() else sys.executable
        for tid, title, filename in q3_scripts:
            t0 = time.perf_counter()
            proc = subprocess.run(
                [py_exec, str(REPO_ROOT / "Q3_Quantum_Attacks" / filename)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            results.append({
                "id": tid,
                "title": title,
                "language": "Python (Qiskit)",
                "passed": proc.returncode == 0 and "PASS" in proc.stdout,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "output": proc.stdout.strip() or proc.stderr.strip(),
            })

    return {"ok": True, "suite": req.suite, "results": results}


# Serve built frontend assets when ui/frontend/dist exists
if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API route not found")
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
