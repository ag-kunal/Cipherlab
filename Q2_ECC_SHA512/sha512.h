// =============================================================================
//  sha512.h  -  SHA-512 hash function (header file)
// =============================================================================
//  WHAT IS A HASH FUNCTION?
//    A hash function takes ANY message (a word, a file, a movie...) and
//    produces a fixed-size "fingerprint". SHA-512 always gives 512 bits
//    (64 bytes, written as 128 hex characters).
//
//  GOOD PROPERTIES:
//    * Same message  -> always the same fingerprint.
//    * Change 1 bit  -> a completely different fingerprint.
//    * You cannot go backwards from the fingerprint to the message.
//
//  HOW TO USE THIS CLASS (two ways):
//    1) One-shot:   SHA512::Digest d = SHA512::hash("abc");
//    2) Streaming:  SHA512 h;  h.update(part1);  h.update(part2);
//                   SHA512::Digest d = h.final();
//    Then SHA512::toHex(d) gives the fingerprint as readable text.
// =============================================================================
#ifndef SHA512_H
#define SHA512_H

#include <cstdint>   // fixed-size integers such as uint64_t (exactly 64 bits)
#include <cstddef>
#include <string>
#include <array>

class SHA512 {
public:
    static const size_t DIGEST_SIZE = 64;    // output size in bytes  (64 * 8 = 512 bits)
    static const size_t BLOCK_SIZE  = 128;   // SHA-512 reads input 128 bytes at a time

    // A Digest is simply 64 bytes.
    typedef std::array<uint8_t, DIGEST_SIZE> Digest;

    SHA512();                                         // start a new hash
    void   reset();                                   // go back to the starting state
    void   update(const uint8_t* data, size_t len);   // feed more bytes
    void   update(const std::string& text);           // feed a string
    Digest final();                                   // finish and get the 64-byte result

    // Shortcuts so you can hash in a single line
    static Digest      hash(const uint8_t* data, size_t len);
    static Digest      hash(const std::string& text);
    static std::string toHex(const Digest& d);        // bytes -> "ddaf35a1..." text

private:
    void processBlock(const uint8_t* block);          // the heart of SHA-512

    uint64_t state_[8];             // 8 working values (a..h), they become the final hash
    uint8_t  buffer_[BLOCK_SIZE];   // holds input bytes until we have a full 128-byte block
    size_t   bufLen_;               // how many bytes are in buffer_ right now
    uint64_t totalBitsLow_;         // total message length in bits ...
    uint64_t totalBitsHigh_;        // ... stored in 128 bits (low half + high half)
};

#endif
