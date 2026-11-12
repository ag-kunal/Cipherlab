// =============================================================================
//  sha512.cpp  -  SHA-512 implemented from scratch (FIPS 180-4)
// =============================================================================
//  THE ALGORITHM IN 4 STEPS
//    Step 1  PAD       Add bytes to the message so its length is a multiple of
//                      128 bytes (and record the original length at the end).
//    Step 2  SPLIT     Cut the padded message into 128-byte blocks.
//    Step 3  MIX       For every block run 80 rounds of mixing that scramble the
//                      block into the 8 working values (the "state").
//    Step 4  OUTPUT    After the last block, join the 8 values -> 512-bit hash.
// =============================================================================
#include "sha512.h"
#include <cstring>   // memcpy

namespace {   // helpers that are private to this file

// -----------------------------------------------------------------------------
// ROUND CONSTANTS. Round number t (0..79) uses ROUND_CONSTANTS[t].
// They are fixed numbers defined by the standard (the first 64 bits of the
// fractional part of the cube roots of the first 80 prime numbers).
// "Nothing-up-my-sleeve" numbers: anyone can check they were not chosen to
// hide a backdoor.
// -----------------------------------------------------------------------------
const uint64_t ROUND_CONSTANTS[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

// -----------------------------------------------------------------------------
// BUILDING BLOCKS used in the mixing rounds. All work on 64-bit numbers.
// -----------------------------------------------------------------------------

// Rotate right: shift bits right, and the bits that fall off the right end
// re-enter on the left.   Example (8 bits): 0b00010011 rotated right by 2 = 0b11000100
inline uint64_t rotateRight(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

// choose(e,f,g): for every bit position, "if e's bit is 1 pick f's bit, else pick g's bit".
inline uint64_t choose(uint64_t e, uint64_t f, uint64_t g) {
    return (e & f) ^ (~e & g);
}

// majority(a,b,c): for every bit position, output the bit that appears at least twice.
inline uint64_t majority(uint64_t a, uint64_t b, uint64_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

// The next two scramble the working values 'a' and 'e' inside each round.
inline uint64_t bigSigma0(uint64_t a) { return rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39); }
inline uint64_t bigSigma1(uint64_t e) { return rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41); }

// The next two are used to EXPAND the 16 input words into 80 words.
inline uint64_t smallSigma0(uint64_t x) { return rotateRight(x, 1)  ^ rotateRight(x, 8)  ^ (x >> 7); }
inline uint64_t smallSigma1(uint64_t x) { return rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >> 6); }

} // end of private helpers


// =============================================================================
//  Constructor / reset: set the 8 starting values
// =============================================================================
SHA512::SHA512() { reset(); }

void SHA512::reset() {
    // Initial values from the standard (first 64 bits of the fractional parts
    // of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17, 19).
    state_[0] = 0x6a09e667f3bcc908ULL;
    state_[1] = 0xbb67ae8584caa73bULL;
    state_[2] = 0x3c6ef372fe94f82bULL;
    state_[3] = 0xa54ff53a5f1d36f1ULL;
    state_[4] = 0x510e527fade682d1ULL;
    state_[5] = 0x9b05688c2b3e6c1fULL;
    state_[6] = 0x1f83d9abfb41bd6bULL;
    state_[7] = 0x5be0cd19137e2179ULL;

    bufLen_       = 0;     // nothing buffered yet
    totalBitsLow_ = 0;     // message length so far = 0
    totalBitsHigh_ = 0;
}


// =============================================================================
//  processBlock: STEP 3 - mix ONE 128-byte block into the state
// =============================================================================
void SHA512::processBlock(const uint8_t* block) {

    // ---- 3a. Turn the 128 bytes into 16 words of 64 bits ("big-endian":
    //          the first byte is the most significant). ------------------------
    uint64_t W[80];                         // the "message schedule"
    for (int t = 0; t < 16; t++) {
        W[t] = 0;
        for (int i = 0; i < 8; i++) {
            W[t] = (W[t] << 8) | block[t * 8 + i];   // append one byte at a time
        }
    }

    // ---- 3b. Expand 16 words into 80 words. Each new word is built from
    //          four earlier ones, so every input bit influences many rounds. ----
    for (int t = 16; t < 80; t++) {
        W[t] = smallSigma1(W[t - 2]) + W[t - 7] + smallSigma0(W[t - 15]) + W[t - 16];
    }

    // ---- 3c. Copy the state into 8 working variables a..h. ------------------
    uint64_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint64_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    // ---- 3d. The 80 rounds. In each round we compute two temporary values
    //          and shift all variables down one place (like a conveyor belt). ---
    for (int t = 0; t < 80; t++) {
        uint64_t temp1 = h + bigSigma1(e) + choose(e, f, g) + ROUND_CONSTANTS[t] + W[t];
        uint64_t temp2 = bigSigma0(a) + majority(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;      // new 'e'
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;  // new 'a'
        // (additions wrap around automatically at 2^64, which is what SHA wants)
    }

    // ---- 3e. Add the result back into the state (so earlier blocks matter). --
    state_[0] += a;  state_[1] += b;  state_[2] += c;  state_[3] += d;
    state_[4] += e;  state_[5] += f;  state_[6] += g;  state_[7] += h;
}


// =============================================================================
//  update: feed bytes in. Full 128-byte blocks are processed immediately,
//          leftover bytes wait in buffer_ until more data arrives.
// =============================================================================
void SHA512::update(const uint8_t* data, size_t len) {

    // Keep track of the total length in BITS (needed for padding later).
    // The length is a 128-bit number stored as two 64-bit halves.
    uint64_t addedBits = (uint64_t)len * 8;
    uint64_t oldLow    = totalBitsLow_;
    totalBitsLow_  += addedBits;
    totalBitsHigh_ += (uint64_t)len >> 61;      // bits that overflow the low half
    if (totalBitsLow_ < oldLow) totalBitsHigh_++;   // carry, like in school addition

    while (len > 0) {
        // How many bytes still fit in the buffer?
        size_t space = BLOCK_SIZE - bufLen_;
        size_t take  = (len < space) ? len : space;

        memcpy(buffer_ + bufLen_, data, take);   // copy them in
        bufLen_ += take;
        data    += take;
        len     -= take;

        if (bufLen_ == BLOCK_SIZE) {             // buffer full -> hash it
            processBlock(buffer_);
            bufLen_ = 0;
        }
    }
}

void SHA512::update(const std::string& text) {
    update((const uint8_t*)text.data(), text.size());
}


// =============================================================================
//  final: STEP 1 (padding) and STEP 4 (output)
// =============================================================================
SHA512::Digest SHA512::final() {

    // Remember the real message length BEFORE padding changes the counters.
    uint64_t lengthHigh = totalBitsHigh_;
    uint64_t lengthLow  = totalBitsLow_;

    // ---- Padding rule:  message + 0x80 + zeros + 16-byte length ------------
    //   * 0x80 = binary 10000000 (a single '1' bit followed by zeros)
    //   * then zero bytes until exactly 112 bytes sit in the current block
    //   * the last 16 bytes of the block hold the original length in bits
    uint8_t oneBit = 0x80;
    update(&oneBit, 1);

    uint8_t zero = 0;
    while (bufLen_ != 112) {
        update(&zero, 1);
    }

    uint8_t lengthBytes[16];                    // length written big-endian
    for (int i = 0; i < 8; i++) {
        lengthBytes[i]     = (uint8_t)(lengthHigh >> (56 - 8 * i));
        lengthBytes[8 + i] = (uint8_t)(lengthLow  >> (56 - 8 * i));
    }
    update(lengthBytes, 16);                    // this completes the block -> hashed

    // ---- Output: write the 8 state words one after another (big-endian) -----
    Digest result;
    for (int word = 0; word < 8; word++) {
        for (int byteIdx = 0; byteIdx < 8; byteIdx++) {
            result[word * 8 + byteIdx] = (uint8_t)(state_[word] >> (56 - 8 * byteIdx));
        }
    }

    reset();            // make the object ready for a new message
    return result;
}


// =============================================================================
//  Convenience functions
// =============================================================================
SHA512::Digest SHA512::hash(const uint8_t* data, size_t len) {
    SHA512 hasher;
    hasher.update(data, len);
    return hasher.final();
}

SHA512::Digest SHA512::hash(const std::string& text) {
    return hash((const uint8_t*)text.data(), text.size());
}

// Convert bytes to hexadecimal text: byte 0xAB -> "ab"
std::string SHA512::toHex(const Digest& d) {
    const char* hexDigits = "0123456789abcdef";
    std::string text;
    for (uint8_t byte : d) {
        text += hexDigits[byte >> 4];      // upper 4 bits
        text += hexDigits[byte & 15];      // lower 4 bits
    }
    return text;
}
