# Assignment 2 - SHA-512 and ECC (NIST P-256) in C++

Everything is written **from scratch** (no OpenSSL, GMP or other crypto libraries) and every
file is heavily commented so a beginner can follow it.

## Quick start (3 commands)
```
make              # compile  (needs g++ with C++11)
./ecc_sha512      # run all tests and demos  (expect: "18 tests passed, 0 failed")
make clean        # delete the compiled program
```
No `make`? Use: `g++ -std=c++11 -O2 -o ecc_sha512 main.cpp sha512.cpp ecc.cpp bigint256.cpp`

Other commands:
```
./ecc_sha512 hash "any text"     # SHA-512 of some text
./ecc_sha512 hashfile myfile     # SHA-512 of a file (compare with: sha512sum myfile)
./ecc_sha512 bench               # speed measurements
```

## Which file should I read first?
| Order | File | What it contains |
|---|---|---|
| 1 | `sha512.h` / `sha512.cpp` | The SHA-512 hash function (pad -> split -> 80 rounds -> output) |
| 2 | `bigint256.h` / `bigint256.cpp` | Big 256-bit numbers and "clock arithmetic" (mod p) |
| 3 | `ecc.h` / `ecc.cpp` | Curve points, scalar multiplication, ECDH key exchange, ECDSA signatures |
| 4 | `main.cpp` | Tests and demos that use everything above (Parts A-D) |
| - | `docs/` | Program output, benchmark data and diagrams used in the report |

## What the program shows
* **Part A - SHA-512:** official NIST test values, example hashes, avalanche effect
* **Part B - ECC maths:** checks such as `n*G = infinity` and `(a+b)G = aG + bG`
* **Part C - ECDH:** Alice and Bob create the same secret without ever sending it
* **Part D - ECDSA:** sign a message with SHA-512, then accept / reject signatures

## Limitations
Learning code only. Scalar multiplication is not constant-time and the modular multiplication
is simple (slow) - do not use it to protect real data.
