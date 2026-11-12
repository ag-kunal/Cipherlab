// =============================================================================
//  bigint256.cpp  -  implementation of the 256-bit number helpers
// =============================================================================
#include "bigint256.h"

// Convert one hex character ('0'-'9','a'-'f') to its value 0..15
static int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// ---------------------------------------------------------------- conversions
U256 U256::fromHex(const std::string& hex) {
    U256 r;
    int nibble = 0;                                   // a nibble = one hex digit = 4 bits
    // read the text from the right end (least significant digit first)
    for (int i = (int)hex.size() - 1; i >= 0 && nibble < 64; i--, nibble++) {
        r.w[nibble / 8] |= (uint32_t)hexValue(hex[i]) << (4 * (nibble % 8));
    }
    return r;
}

U256 U256::fromBytes(const uint8_t* b) {
    U256 r;
    for (int i = 0; i < 32; i++) {                    // b[0] is the most significant byte
        int fromRight = 31 - i;
        r.w[fromRight / 4] |= (uint32_t)b[i] << (8 * (fromRight % 4));
    }
    return r;
}

void U256::toBytes(uint8_t* b) const {
    for (int i = 0; i < 32; i++) {
        int fromRight = 31 - i;
        b[i] = (uint8_t)(w[fromRight / 4] >> (8 * (fromRight % 4)));
    }
}

std::string U256::toHex() const {
    const char* digits = "0123456789abcdef";
    std::string s;
    for (int limb = 7; limb >= 0; limb--)             // most significant limb first
        for (int nib = 7; nib >= 0; nib--)
            s += digits[(w[limb] >> (4 * nib)) & 15];
    return s;
}

// ---------------------------------------------------------------- simple queries
bool U256::isZero() const {
    for (int i = 0; i < 8; i++) if (w[i] != 0) return false;
    return true;
}

int U256::bitLength() const {
    for (int i = 255; i >= 0; i--) if (bit(i)) return i + 1;
    return 0;
}

int cmp(const U256& a, const U256& b) {
    for (int i = 7; i >= 0; i--) {                    // compare from the biggest limb down
        if (a.w[i] > b.w[i]) return 1;
        if (a.w[i] < b.w[i]) return -1;
    }
    return 0;
}

// ---------------------------------------------------------------- plain add / subtract
// Works like school addition, one limb at a time, passing a carry along.
uint32_t addRaw(U256& r, const U256& a, const U256& b) {
    uint64_t carry = 0;
    for (int i = 0; i < 8; i++) {
        carry += (uint64_t)a.w[i] + b.w[i];
        r.w[i] = (uint32_t)carry;                     // keep the low 32 bits
        carry >>= 32;                                 // the rest carries to the next limb
    }
    return (uint32_t)carry;
}

uint32_t subRaw(U256& r, const U256& a, const U256& b) {
    int64_t borrow = 0;
    for (int i = 0; i < 8; i++) {
        int64_t diff = (int64_t)a.w[i] - b.w[i] - borrow;
        borrow = (diff < 0) ? 1 : 0;
        r.w[i] = (uint32_t)diff;
    }
    return (uint32_t)borrow;
}

// ---------------------------------------------------------------- modular arithmetic
// If a >= m, subtract m once.
U256 reduce(const U256& a, const U256& m) {
    U256 r = a;
    if (cmp(r, m) >= 0) subRaw(r, r, m);
    return r;
}

// (a + b) mod m : add, and if we went past m (or past 2^256) subtract m once.
U256 addMod(const U256& a, const U256& b, const U256& m) {
    U256 r;
    uint32_t carry = addRaw(r, a, b);
    if (carry || cmp(r, m) >= 0) subRaw(r, r, m);
    return r;
}

// (a - b) mod m : subtract, and if the answer went negative, add m back.
U256 subMod(const U256& a, const U256& b, const U256& m) {
    U256 r;
    uint32_t borrow = subRaw(r, a, b);
    if (borrow) addRaw(r, r, m);
    return r;
}

// (a * b) mod m
//   Part 1: multiply like in school (limb by limb) -> a 512-bit product.
//   Part 2: reduce it mod m using "binary long division": go through the
//           product bit by bit from the top; keep a remainder, double it,
//           bring down the next bit, and subtract m whenever it gets too big.
//   This is simple to understand but slower than what real libraries do.
U256 mulMod(const U256& a, const U256& b, const U256& m) {
    uint32_t product[16] = {0};                       // 16 limbs = 512 bits

    for (int i = 0; i < 8; i++) {                     // Part 1
        uint64_t carry = 0;
        for (int j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)a.w[i] * b.w[j] + product[i + j] + carry;
            product[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        product[i + 8] = (uint32_t)carry;
    }

    U256 remainder;                                   // Part 2 (starts at 0)
    for (int bitPos = 511; bitPos >= 0; bitPos--) {
        uint32_t topBit = remainder.w[7] >> 31;       // the bit that will fall off when doubling

        for (int k = 7; k > 0; k--)                   // remainder = remainder * 2 ...
            remainder.w[k] = (remainder.w[k] << 1) | (remainder.w[k - 1] >> 31);
        remainder.w[0] = (remainder.w[0] << 1)
                       | ((product[bitPos / 32] >> (bitPos % 32)) & 1);   // ... + next bit

        if (topBit || cmp(remainder, m) >= 0)         // too big? subtract m
            subRaw(remainder, remainder, m);
    }
    return remainder;
}

// (a ^ e) mod m using "square and multiply": scan the bits of e from the top.
// For each bit: square the result; if the bit is 1, also multiply by a.
U256 powMod(const U256& a, const U256& e, const U256& m) {
    U256 result(1);
    int bits = e.bitLength();
    for (int i = bits - 1; i >= 0; i--) {
        result = mulMod(result, result, m);           // square
        if (e.bit(i)) result = mulMod(result, a, m); // multiply
    }
    return result;
}

// Modular inverse: the number x such that (a * x) mod p = 1.
// Fermat's little theorem says: for a prime p, a^(p-1) = 1 (mod p),
// therefore the inverse of a is a^(p-2).
U256 invMod(const U256& a, const U256& p) {
    U256 exponent;
    subRaw(exponent, p, U256(2));                     // exponent = p - 2
    return powMod(a, exponent, p);
}
