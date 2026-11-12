# Q3 - Shor's and Grover's algorithms (Python, Qiskit)

| File | What it demonstrates |
|---|---|
| `shor_rsa.py` | Shor's period finding recovers the factors of a toy RSA modulus N = 15, then the private key |
| `shor_ecc.py` | Quantum Fourier sampling recovers the private scalar on a toy elliptic curve (y^2 = x^3 + x + 2 mod 17, order 8) |
| `grover_aes.py` | Grover search over a restricted 4-bit AES-128 key family |
| `grover_sha512.py` | Grover search for a 4-bit SHA-512 pre-image |

## Run
```
pip install -r requirements.txt
python shor_rsa.py
python shor_ecc.py
python grover_aes.py
python grover_sha512.py
```
Screenshots of the outputs are in `outputs/`.

## Scope
These are **toy simulations** on a classical computer (state-vector simulator). They show how the
algorithms work, not a practical attack on real RSA, ECC, AES-128 or SHA-512.
