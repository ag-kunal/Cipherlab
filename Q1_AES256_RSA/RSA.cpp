#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <limits>

using namespace std;
using int64 = long long;

// EDUCATIONAL DEMONSTRATION ONLY.
// The values used in main() are intentionally too small for real-world security.

int64 modPow(int64 base, int64 exponent, int64 modulus) {
    if (modulus <= 0 || exponent < 0) {
        throw invalid_argument("Invalid modulus or exponent.");
    }

    int64 result = 1 % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

int64 extendedGCD(int64 a, int64 b, int64& x, int64& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }

    int64 x1, y1;
    int64 g = extendedGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}

int64 modInverse(int64 a, int64 modulus) {
    int64 x, y;
    int64 g = extendedGCD(a, modulus, x, y);

    if (g != 1) {
        throw invalid_argument("Modular inverse does not exist: gcd must be 1.");
    }
    return (x % modulus + modulus) % modulus;
}

bool isPrime(int64 n) {
    if (n < 2) return false;
    if (n == 2) return true;
    if (n % 2 == 0) return false;

    for (int64 divisor = 3; divisor <= n / divisor; divisor += 2) {
        if (n % divisor == 0) return false;
    }
    return true;
}

int64 gcdValue(int64 a, int64 b) {
    while (b != 0) {
        int64 remainder = a % b;
        a = b;
        b = remainder;
    }
    return a;
}

struct RSAKeyPair {
    int64 n;
    int64 phi;
    int64 e;
    int64 d;
};

RSAKeyPair generateDemoKeys(int64 p, int64 q, int64 e) {
    if (!isPrime(p) || !isPrime(q)) {
        throw invalid_argument("p and q must both be prime.");
    }
    if (p == q) {
        throw invalid_argument("p and q must be distinct primes.");
    }
    if (p > numeric_limits<int64>::max() / q) {
        throw overflow_error("p*q would overflow int64.");
    }

    const int64 n = p * q;
    // The selected classroom primes are small enough for this calculation.
    const int64 phi = (p - 1) * (q - 1);

    if (e <= 1 || e >= phi) {
        throw invalid_argument("e must satisfy 1 < e < phi(n).");
    }
    if (gcdValue(e, phi) != 1) {
        throw invalid_argument("e must be coprime to phi(n).");
    }

    const int64 d = modInverse(e, phi);
    return {n, phi, e, d};
}

int64 encryptNumber(int64 message, int64 e, int64 n) {
    if (message < 0 || message >= n) {
        throw invalid_argument("Message must satisfy 0 <= M < n.");
    }
    return modPow(message, e, n);
}

int64 decryptNumber(int64 ciphertext, int64 d, int64 n) {
    if (ciphertext < 0 || ciphertext >= n) {
        throw invalid_argument("Ciphertext must satisfy 0 <= C < n.");
    }
    return modPow(ciphertext, d, n);
}

// Teaching demonstration only: encrypts each ASCII byte separately.
// This is textbook RSA and must not be used to protect real messages.
vector<int64> encryptText(const string& message, int64 e, int64 n) {
    vector<int64> ciphertext;
    ciphertext.reserve(message.size());
    for (unsigned char ch : message) {
        ciphertext.push_back(encryptNumber(static_cast<int64>(ch), e, n));
    }
    return ciphertext;
}

string decryptText(const vector<int64>& ciphertext, int64 d, int64 n) {
    string message;
    message.reserve(ciphertext.size());
    for (int64 value : ciphertext) {
        const int64 decoded = decryptNumber(value, d, n);
        if (decoded < 0 || decoded > 255) {
            throw runtime_error("Decrypted value is outside the byte range.");
        }
        message.push_back(static_cast<char>(static_cast<unsigned char>(decoded)));
    }
    return message;
}

int main() {
    try {
        // Four-digit primes: moderate for a classroom example, NOT secure RSA keys.
        const int64 p = 1009;
        const int64 q = 1013;
        const int64 e = 65537;

        const RSAKeyPair keys = generateDemoKeys(p, q, e);

        cout << "=== RSA Cryptosystem: Educational Demonstration ===\n";
        cout << "p = " << p << '\n';
        cout << "q = " << q << '\n';
        cout << "n = p * q = " << keys.n << '\n';
        cout << "phi(n) = (p - 1) * (q - 1) = " << keys.phi << '\n';
        cout << "Public key (n, e) = (" << keys.n << ", " << keys.e << ")\n";
        cout << "Private exponent d = " << keys.d << "\n\n";

        const int64 originalNumber = 65;
        const int64 encryptedNumber = encryptNumber(originalNumber, keys.e, keys.n);
        const int64 decryptedNumber = decryptNumber(encryptedNumber, keys.d, keys.n);

        cout << "Numeric demonstration:\n";
        cout << "Original number: " << originalNumber << '\n';
        cout << "Ciphertext: " << encryptedNumber << '\n';
        cout << "Decrypted number: " << decryptedNumber << '\n';
        cout << "Numeric test: "
             << (decryptedNumber == originalNumber ? "PASS" : "FAIL") << "\n\n";

        const string originalText = "Hello RSA!";
        const vector<int64> ciphertext = encryptText(originalText, keys.e, keys.n);
        const string recoveredText = decryptText(ciphertext, keys.d, keys.n);

        cout << "Text round-trip demonstration (each ASCII byte encrypted separately):\n";
        cout << "Original text: " << originalText << '\n';
        cout << "Ciphertext integers: ";
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            if (i != 0) cout << ' ';
            cout << ciphertext[i];
        }
        cout << '\n';
        cout << "Decrypted text: " << recoveredText << '\n';
        cout << "Text test: " << (recoveredText == originalText ? "PASS" : "FAIL") << '\n';

        return (decryptedNumber == originalNumber && recoveredText == originalText) ? 0 : 1;
    } catch (const exception& ex) {
        cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
}
