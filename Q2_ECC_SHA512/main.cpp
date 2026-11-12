// =============================================================================
//  main.cpp  -  Test and demo program for ECC (P-256) and SHA-512
// =============================================================================
//  HOW TO RUN
//    ./ecc_sha512                 -> all tests + demos (the normal way)
//    ./ecc_sha512 hash "text"     -> print the SHA-512 of some text
//    ./ecc_sha512 hashfile FILE   -> print the SHA-512 of a file
//    ./ecc_sha512 bench           -> speed measurements
//
//  PROGRAM FLOW
//    Part A  SHA-512 : known-answer tests, examples, avalanche effect
//    Part B  ECC     : mathematical self-checks on the curve
//    Part C  ECDH    : Alice and Bob create a shared secret
//    Part D  ECDSA   : sign a message and verify the signature
// =============================================================================
#include "sha512.h"
#include "ecc.h"

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <cstring>
#include <vector>

using namespace std;

// ----------------------------------------------------------------------------
//  Small helper functions used by the tests
// ----------------------------------------------------------------------------
static int testsPassed = 0;
static int testsFailed = 0;

// Print "[PASS]" or "[FAIL]" for one test and remember the result.
static void check(const string& description, bool ok) {
    cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << description << "\n";
    if (ok) testsPassed++; else testsFailed++;
}

static void printHeading(const string& title) {
    cout << "\n==============================================================\n"
         << " " << title << "\n"
         << "==============================================================\n";
}

static void printPoint(const string& label, const Point& P) {
    cout << label << "\n    x = " << P.x.toHex() << "\n    y = " << P.y.toHex() << "\n";
}

// How many bits differ between two digests? (used for the avalanche test)
static int countDifferentBits(const SHA512::Digest& a, const SHA512::Digest& b) {
    int count = 0;
    for (size_t i = 0; i < a.size(); i++) {
        unsigned char diff = a[i] ^ b[i];            // XOR: 1 where the bits differ
        while (diff) { count += diff & 1; diff >>= 1; }
    }
    return count;
}

// ============================================================================
//  PART A: SHA-512
// ============================================================================
static void partA_sha512() {
    printHeading("PART A: SHA-512");

    // ---- A1. Known-answer tests: compare with official NIST results --------
    cout << "\nA1. Known-answer tests (official values published by NIST)\n";

    check("SHA-512 of empty text \"\"",
          SHA512::toHex(SHA512::hash("")) ==
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    check("SHA-512 of \"abc\"",
          SHA512::toHex(SHA512::hash("abc")) ==
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    check("SHA-512 of the 112-byte NIST message (needs 2 blocks)",
          SHA512::toHex(SHA512::hash(
          "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")) ==
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
          "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

    // One million letters 'a', fed in 1000 pieces. This also tests the
    // "streaming" feature (update called many times).
    SHA512 streamingHasher;
    string piece(1000, 'a');
    for (int i = 0; i < 1000; i++) streamingHasher.update(piece);
    check("SHA-512 of 1,000,000 x 'a' (streaming input)",
          SHA512::toHex(streamingHasher.final()) ==
          "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
          "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

    // ---- A2. Example hashes -------------------------------------------------
    cout << "\nA2. Example hashes (each is 128 hex characters = 512 bits)\n";
    string examples[] = {"", "abc", "Hello, World!", "The quick brown fox jumps over the lazy dog"};
    for (const string& text : examples) {
        string hex = SHA512::toHex(SHA512::hash(text));
        cout << "\n  Message : \"" << text << "\"\n";
        cout << "  SHA-512 : " << hex.substr(0, 64) << "\n"      // split in two lines
             << "            " << hex.substr(64) << "\n";
    }

    // ---- A3. Avalanche effect ----------------------------------------------
    // A good hash changes about HALF of its output bits when the input changes
    // by even a single bit.
    cout << "\nA3. Avalanche effect (change just 1 bit of the input)\n";
    string original = "The quick brown fox jumps over the lazy dog";
    string modified = original;
    modified[0] = modified[0] ^ 0x01;                              // flip the lowest bit of 'T'
    int different = countDifferentBits(SHA512::hash(original), SHA512::hash(modified));
    cout << "  Input 1 : " << original << "\n";
    cout << "  Input 2 : " << modified << "   (1 bit changed in the first letter)\n";
    cout << "  Output bits that changed: " << different << " out of 512  ("
         << fixed << setprecision(1) << different * 100.0 / 512 << "%, ideal is about 50%)\n";
}

// ============================================================================
//  PART B: ECC math self-checks
// ============================================================================
static void partB_eccMath(const ECC& ecc) {
    printHeading("PART B: ECC (NIST P-256) mathematical checks");
    cout << "\nThese checks prove that our point arithmetic is correct.\n\n";

    // B1. The base point must satisfy the curve equation.
    check("Base point G lies on the curve", ecc.isOnCurve(ecc.G()));

    // B2. Compare 2G and 3G with the official published values.
    Point twoG = ecc.dbl(ecc.G());
    check("2G equals the official published value",
          twoG.x.toHex() == "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978" &&
          twoG.y.toHex() == "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");

    Point threeG_byAdding = ecc.add(twoG, ecc.G());                // 2G + G
    Point threeG_byScalar = ecc.scalarMul(U256(3), ecc.G());       // 3 * G
    check("2G + G gives the same point as 3 * G",
          threeG_byAdding.x == threeG_byScalar.x && threeG_byAdding.y == threeG_byScalar.y);
    check("3G equals the official published value",
          threeG_byAdding.x.toHex() == "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c");

    // B3. The "order" n: adding G exactly n times wraps around to infinity.
    check("n * G = point at infinity (n is the order of G)", ecc.scalarMul(ecc.n(), ecc.G()).inf);

    U256 nMinus1;
    subRaw(nMinus1, ecc.n(), U256(1));
    Point almostWrapped = ecc.scalarMul(nMinus1, ecc.G());
    Point minusG        = ecc.negate(ecc.G());
    check("(n-1) * G equals -G", almostWrapped.x == minusG.x && almostWrapped.y == minusG.y);

    check("P + (-P) = point at infinity", ecc.add(twoG, ecc.negate(twoG)).inf);

    // B4. Distributive law with random numbers:  (a + b) * G  =  a*G + b*G
    U256 a = ecc.randomScalar();
    U256 b = ecc.randomScalar();
    Point left  = ecc.scalarMul(addMod(a, b, ecc.n()), ecc.G());
    Point right = ecc.add(ecc.scalarMul(a, ecc.G()), ecc.scalarMul(b, ecc.G()));
    check("(a + b) * G = a*G + b*G  for random a and b", left.x == right.x && left.y == right.y);

    check("A random public key is on the curve", ecc.isOnCurve(ecc.publicKey(a)));
}

// ============================================================================
//  PART C: ECDH key agreement
// ============================================================================
static void partC_ecdh(const ECC& ecc, U256& alicePrivate, Point& alicePublic,
                       U256& bobPrivate, Point& bobPublic) {
    printHeading("PART C: ECDH key agreement (Alice and Bob)");

    cout << "\nStep 1: each person creates a key pair.\n";
    alicePrivate = ecc.randomScalar();
    alicePublic  = ecc.publicKey(alicePrivate);
    bobPrivate   = ecc.randomScalar();
    bobPublic    = ecc.publicKey(bobPrivate);

    cout << "\n  Alice private key  d_A = " << alicePrivate.toHex() << "   (secret)\n";
    printPoint("  Alice public key   Q_A = d_A * G   (shared openly)", alicePublic);
    cout << "\n  Bob   private key  d_B = " << bobPrivate.toHex() << "   (secret)\n";
    printPoint("  Bob   public key   Q_B = d_B * G   (shared openly)", bobPublic);

    cout << "\nStep 2: they swap PUBLIC keys and each computes the shared secret.\n";
    U256 aliceSecret = ecc.ecdh(alicePrivate, bobPublic);          // d_A * Q_B
    U256 bobSecret   = ecc.ecdh(bobPrivate, alicePublic);          // d_B * Q_A
    cout << "  Alice computes d_A * Q_B -> " << aliceSecret.toHex() << "\n";
    cout << "  Bob   computes d_B * Q_A -> " << bobSecret.toHex() << "\n\n";
    check("Alice and Bob obtained the SAME shared secret", aliceSecret == bobSecret);

    cout << "\nStep 3: turn the secret into an encryption key with SHA-512.\n";
    uint8_t secretBytes[32];
    aliceSecret.toBytes(secretBytes);
    string key = SHA512::toHex(SHA512::hash(secretBytes, 32)).substr(0, 64);
    cout << "  256-bit key = first 64 hex characters of SHA-512(secret)\n  " << key << "\n";
}

// ============================================================================
//  PART D: ECDSA digital signatures
// ============================================================================
static void partD_ecdsa(const ECC& ecc, const U256& alicePrivate, const Point& alicePublic,
                        const Point& bobPublic) {
    printHeading("PART D: ECDSA digital signature (hash = SHA-512)");

    string message = "Transfer Rs. 5000 to account 1234567890";
    cout << "\nAlice signs this message with her PRIVATE key:\n  \"" << message << "\"\n";

    Signature sig = ecc.sign(alicePrivate, message);
    cout << "\n  Signature part r = " << sig.r.toHex() << "\n";
    cout << "  Signature part s = " << sig.s.toHex() << "\n\n";

    cout << "Anyone can now verify using Alice's PUBLIC key:\n";
    check("Correct message + correct signature -> ACCEPTED", ecc.verify(alicePublic, message, sig));
    check("Message changed after signing       -> REJECTED", !ecc.verify(alicePublic, message + "0", sig));
    check("Checked with the wrong public key   -> REJECTED", !ecc.verify(bobPublic, message, sig));

    Signature forged = sig;
    forged.s = addMod(forged.s, U256(1), ecc.n());                 // alter the signature slightly
    check("Signature altered slightly          -> REJECTED", !ecc.verify(alicePublic, message, forged));
}

// ============================================================================
//  BENCHMARKS (run with:  ./ecc_sha512 bench)
// ============================================================================
static double secondsSince(chrono::steady_clock::time_point start) {
    return chrono::duration<double>(chrono::steady_clock::now() - start).count();
}

static void runBenchmarks() {
    cout << "\n=== Benchmark: SHA-512 speed ===\n";
    cout << "size_bytes,time_ms,throughput_MBps\n";
    size_t sizes[] = {64, 1024, 16 * 1024, 256 * 1024, 1024 * 1024, 16 * 1024 * 1024};
    for (size_t size : sizes) {
        vector<uint8_t> data(size, 0x61);
        int repeats = (int)max<size_t>(1, (32u * 1024 * 1024) / size);   // hash ~32 MB in total
        auto start = chrono::steady_clock::now();
        for (int i = 0; i < repeats; i++) {
            volatile uint8_t sink = SHA512::hash(data.data(), size)[0];
            (void)sink;
        }
        double seconds = secondsSince(start) / repeats;
        cout << size << "," << fixed << setprecision(4) << seconds * 1000 << ","
             << setprecision(2) << (size / 1048576.0) / seconds << "\n";
    }

    cout << "\n=== Benchmark: ECC P-256 speed (average of 20 runs) ===\n";
    cout << "operation,time_ms\n";
    ECC ecc;
    const int RUNS = 20;
    U256  d = ecc.randomScalar();
    Point Q = ecc.publicKey(d);

    auto start = chrono::steady_clock::now();
    for (int i = 0; i < RUNS; i++) ecc.scalarMul(ecc.randomScalar(), ecc.G());
    cout << "Scalar multiplication (kG)," << fixed << setprecision(3) << secondsSince(start) * 1000 / RUNS << "\n";

    start = chrono::steady_clock::now();
    for (int i = 0; i < RUNS; i++) ecc.ecdh(d, Q);
    cout << "ECDH shared secret," << secondsSince(start) * 1000 / RUNS << "\n";

    start = chrono::steady_clock::now();
    Signature s;
    for (int i = 0; i < RUNS; i++) s = ecc.sign(d, "benchmark message");
    cout << "ECDSA sign (SHA-512)," << secondsSince(start) * 1000 / RUNS << "\n";

    start = chrono::steady_clock::now();
    for (int i = 0; i < RUNS; i++) ecc.verify(Q, "benchmark message", s);
    cout << "ECDSA verify (SHA-512)," << secondsSince(start) * 1000 / RUNS << "\n";
}

// ============================================================================
//  main: read the command line and run what the user asked for
// ============================================================================
int main(int argc, char** argv) {

    // ./ecc_sha512 hash "some text"
    if (argc >= 3 && strcmp(argv[1], "hash") == 0) {
        cout << SHA512::toHex(SHA512::hash(string(argv[2]))) << "\n";
        return 0;
    }

    // ./ecc_sha512 hashfile path/to/file
    if (argc >= 3 && strcmp(argv[1], "hashfile") == 0) {
        ifstream file(argv[2], ios::binary);
        if (!file) { cerr << "Cannot open file: " << argv[2] << "\n"; return 1; }
        SHA512 hasher;
        char chunk[65536];
        while (file.read(chunk, sizeof chunk) || file.gcount() > 0)
            hasher.update((const uint8_t*)chunk, (size_t)file.gcount());
        cout << SHA512::toHex(hasher.final()) << "  " << argv[2] << "\n";
        return 0;
    }

    // ./ecc_sha512 bench
    if (argc >= 2 && strcmp(argv[1], "bench") == 0) {
        runBenchmarks();
        return 0;
    }

    // ---- default: run every part -------------------------------------------
    cout << "######  Assignment 2: SHA-512 and ECC (NIST P-256)  ######\n";
    ECC ecc;

    U256 alicePrivate, bobPrivate;
    Point alicePublic, bobPublic;

    partA_sha512();
    partB_eccMath(ecc);
    partC_ecdh(ecc, alicePrivate, alicePublic, bobPrivate, bobPublic);
    partD_ecdsa(ecc, alicePrivate, alicePublic, bobPublic);

    cout << "\n==============================================================\n";
    cout << " RESULT: " << testsPassed << " tests passed, " << testsFailed << " failed\n";
    cout << "==============================================================\n";
    return testsFailed ? 1 : 0;
}
