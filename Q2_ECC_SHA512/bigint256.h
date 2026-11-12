// =============================================================================
//  bigint256.h  -  very large (256-bit) whole numbers
// =============================================================================
//  WHY DO WE NEED THIS?
//    A normal C++ integer holds at most 64 bits. Elliptic-curve cryptography
//    uses numbers with 256 bits (about 78 decimal digits), so we build our own.
//
//  HOW IS A 256-BIT NUMBER STORED?
//    As 8 "limbs" (pieces) of 32 bits each, least significant piece first:
//         value = w[0] + w[1]*2^32 + w[2]*2^64 + ... + w[7]*2^224
//
//  MODULAR ARITHMETIC (clock arithmetic):
//    "a mod m" means the remainder after dividing by m.
//    On a 12-hour clock, 10 + 5 = 15 -> 3 (that is "mod 12").
//    ECC does all its maths "mod p" (a huge prime) so numbers never grow beyond
//    256 bits.
// =============================================================================
#ifndef BIGINT256_H
#define BIGINT256_H

#include <cstdint>
#include <string>

struct U256 {
    uint32_t w[8];                                    // the 8 limbs

    U256()                { for (int i = 0; i < 8; i++) w[i] = 0; }   // value 0
    explicit U256(uint32_t v) { for (int i = 0; i < 8; i++) w[i] = 0; w[0] = v; } // small value

    static U256 fromHex(const std::string& hex);      // "ff01..." -> number
    static U256 fromBytes(const uint8_t* b32);        // 32 bytes (big-endian) -> number
    void        toBytes(uint8_t* b32) const;          // number -> 32 bytes
    std::string toHex() const;                        // number -> 64 hex characters

    bool isZero() const;
    bool isOdd()  const { return w[0] & 1; }
    int  bit(int i) const { return (w[i / 32] >> (i % 32)) & 1; }   // read bit number i
    int  bitLength() const;                           // position of the highest 1-bit
};

// Compare two numbers: returns -1 if a<b, 0 if a==b, +1 if a>b
int cmp(const U256& a, const U256& b);
inline bool operator==(const U256& a, const U256& b) { return cmp(a, b) == 0; }
inline bool operator!=(const U256& a, const U256& b) { return cmp(a, b) != 0; }

// Plain add / subtract (result wraps around at 2^256). Return the carry / borrow.
uint32_t addRaw(U256& result, const U256& a, const U256& b);
uint32_t subRaw(U256& result, const U256& a, const U256& b);

// ---- Modular arithmetic: inputs must already be smaller than m ----
U256 addMod(const U256& a, const U256& b, const U256& m);     // (a + b) mod m
U256 subMod(const U256& a, const U256& b, const U256& m);     // (a - b) mod m
U256 mulMod(const U256& a, const U256& b, const U256& m);     // (a * b) mod m
U256 powMod(const U256& a, const U256& e, const U256& m);     // (a ^ e) mod m
U256 invMod(const U256& a, const U256& primeM);               // 1/a mod m  (m must be prime)
U256 reduce(const U256& a, const U256& m);                    // a mod m   (when a < 2m)

#endif
