# AES-256 Encryption and Decryption in C++

This package contains an educational implementation of AES-256 block encryption and decryption, along with an assignment report and a known-answer test.

## Package contents

- `AES256.cpp` — complete standalone C++ implementation of AES-256 encryption and decryption.
- `AES256_Assignment_Report.docx` — editable report for the assignment.
- `AES256_Assignment_Report.pdf` — PDF version of the report.
- `TEST_RESULTS.txt` — expected and observed test output.

## Requirements

- A C++ compiler with C++17 support (for example, GCC or MinGW-w64 g++).
- Windows, Linux, or macOS terminal.

## Compile and run

### Windows PowerShell (MinGW-w64 / GCC)

```powershell
g++ -std=c++17 -O2 -Wall -Wextra -pedantic AES256.cpp -o AES256.exe
.\AES256.exe
```

### Linux or macOS

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic AES256.cpp -o AES256
./AES256
```

## Expected output

```text
Ciphertext: 8EA2B7CA516745BFEAFC49904B496089
Encryption test: PASS
Decrypted:  00112233445566778899AABBCCDDEEFF
Decryption test: PASS
```

The program returns exit code `0` when both tests pass and a non-zero exit code if either check fails.

## Before submitting

1. Replace the cover-page placeholders in the report with your name, roll number, course, instructor, department/institution, and submission date.
2. Review the report and source code so you can explain the implementation in your own words.
3. Follow your instructor's rules on attribution and permitted assistance.

## Scope and security note

This is a learning implementation that encrypts one 16-byte block with a fixed test key. It demonstrates AES-256 mechanics and a reference test vector; it does not implement a message format, padding, a mode of operation, nonce management, or authentication. Do not use this educational code to protect real data. Real applications should use a reviewed cryptographic library and an appropriate authenticated-encryption construction, such as AES-GCM, with correct nonce handling.
