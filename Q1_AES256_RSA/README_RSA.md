# RSA Cryptosystem in C++ — Assignment Package

## Contents
- `RSA.cpp` — standalone C++17 demonstration of RSA key generation, encryption, and decryption.
- `RSA_Assignment_Report.docx` — editable assignment report. Fill in the cover-page details.
- `RSA_Assignment_Report.pdf` — printable copy of the report.
- `TEST_RESULTS.txt` — test parameters and observed program output.

## Compile and run

### Windows PowerShell (with MinGW g++)
```powershell
g++ -std=c++17 -O2 -Wall -Wextra RSA.cpp -o rsa_demo.exe
.\rsa_demo.exe
```

### Linux / macOS
```bash
g++ -std=c++17 -O2 -Wall -Wextra RSA.cpp -o rsa_demo
./rsa_demo
```

## Example parameters
The example uses the four-digit primes `p = 1009` and `q = 1013`, along with `e = 65537`. This gives `n = 1,022,117` and `phi(n) = 1,020,096`. These are moderately sized for a classroom demonstration, and work with ordinary `long long` arithmetic.

**Important:** These values are not secure RSA key sizes. They are intentionally small enough for a student assignment and can be factored quickly. The text example also encrypts each ASCII byte independently using textbook RSA, which is deterministic and insecure for real messages. Do not use this program for real-world security.

## What is implemented
1. Trial-division prime checking for the example inputs.
2. Calculation of `n = p*q` and `phi(n) = (p-1)*(q-1)`.
3. Validation of `e` and calculation of private exponent `d` using Extended Euclid.
4. Modular exponentiation by squaring.
5. Numeric encryption/decryption and a short text round-trip demonstration.
