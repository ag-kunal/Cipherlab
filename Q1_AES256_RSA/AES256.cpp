#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

using Byte = std::uint8_t;
using State = std::array<std::array<Byte, 4>, 4>; // state[row][column]
using Word = std::array<Byte, 4>;
using ExpandedKey = std::array<Word, 60>; // AES-256: 60 words = 15 round keys

constexpr std::array<Byte, 256> SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Build the inverse S-box by reversing the SBOX mapping:
// if SBOX[i] == j, then INV_SBOX[j] == i.
constexpr std::array<Byte, 256> makeInverseSBox() {
    std::array<Byte, 256> inverse{};
    for (int i = 0; i < 256; ++i) {
        inverse[SBOX[i]] = static_cast<Byte>(i);
    }
    return inverse;
}

constexpr auto INV_SBOX = makeInverseSBox();

constexpr std::array<Byte, 8> RCON = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40
};

Word rotWord(const Word& word) {
    return {word[1], word[2], word[3], word[0]};
}

Word subWord(const Word& word) {
    return {
        SBOX[word[0]], SBOX[word[1]], SBOX[word[2]], SBOX[word[3]]
    };
}

ExpandedKey keyExpansion(const std::array<Byte, 32>& key) {
    ExpandedKey expandedKey{};

    // The 32-byte master key becomes the first 8 words.
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            expandedKey[i][j] = key[4 * i + j];
        }
    }

    // AES-256 expands the key to 60 words.
    for (int i = 8; i < 60; ++i) {
        Word temp = expandedKey[i - 1];

        if (i % 8 == 0) {
            temp = subWord(rotWord(temp));
            temp[0] ^= RCON[i / 8];
        } else if (i % 8 == 4) {
            // AES-256-specific extra SubWord step.
            temp = subWord(temp);
        }

        for (int j = 0; j < 4; ++j) {
            expandedKey[i][j] = expandedKey[i - 8][j] ^ temp[j];
        }
    }

    return expandedKey;
}

State bytesToState(const std::array<Byte, 16>& bytes) {
    State state{};
    for (int i = 0; i < 16; ++i) {
        state[i % 4][i / 4] = bytes[i];
    }
    return state;
}

std::array<Byte, 16> stateToBytes(const State& state) {
    std::array<Byte, 16> bytes{};
    for (int i = 0; i < 16; ++i) {
        bytes[i] = state[i % 4][i / 4];
    }
    return bytes;
}

void addRoundKey(State& state, const ExpandedKey& expandedKey, int round) {
    for (int c = 0; c < 4; ++c) {
        for (int r = 0; r < 4; ++r) {
            state[r][c] ^= expandedKey[round * 4 + c][r];
        }
    }
}

void subBytes(State& state) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = SBOX[state[r][c]];
        }
    }
}

void shiftRows(State& state) {
    State oldState = state;
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = oldState[r][(c + r) % 4];
        }
    }
}

Byte xtime(Byte value) {
    // Multiply by x (02 in AES field); reduce with 1B if the high bit was set.
    if (value & 0x80) {
        return static_cast<Byte>((value << 1) ^ 0x1B);
    }
    return static_cast<Byte>(value << 1);
}

void mixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        const Byte a0 = state[0][c];
        const Byte a1 = state[1][c];
        const Byte a2 = state[2][c];
        const Byte a3 = state[3][c];

        const Byte a0x2 = xtime(a0);
        const Byte a1x2 = xtime(a1);
        const Byte a2x2 = xtime(a2);
        const Byte a3x2 = xtime(a3);

        const Byte a0x3 = a0x2 ^ a0;
        const Byte a1x3 = a1x2 ^ a1;
        const Byte a2x3 = a2x2 ^ a2;
        const Byte a3x3 = a3x2 ^ a3;

        state[0][c] = a0x2 ^ a1x3 ^ a2 ^ a3;
        state[1][c] = a0 ^ a1x2 ^ a2x3 ^ a3;
        state[2][c] = a0 ^ a1 ^ a2x2 ^ a3x3;
        state[3][c] = a0x3 ^ a1 ^ a2 ^ a3x2;
    }
}

void invSubBytes(State& state) {
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            state[r][c] = INV_SBOX[state[r][c]];
        }
    }
}

void invShiftRows(State& state) {
    State oldState = state;
    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 4; ++c) {
            // Undo the left rotation by shifting each row right by r.
            state[r][c] = oldState[r][(c - r + 4) % 4];
        }
    }
}

Byte gfMultiply(Byte a, Byte b) {
    Byte result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }

        const bool highBitSet = (a & 0x80) != 0;
        a = static_cast<Byte>(a << 1);
        if (highBitSet) {
            a ^= 0x1B;
        }
        b = static_cast<Byte>(b >> 1);
    }
    return result;
}

void invMixColumns(State& state) {
    for (int c = 0; c < 4; ++c) {
        const Byte a0 = state[0][c];
        const Byte a1 = state[1][c];
        const Byte a2 = state[2][c];
        const Byte a3 = state[3][c];

        state[0][c] = gfMultiply(a0, 0x0E) ^ gfMultiply(a1, 0x0B)
                    ^ gfMultiply(a2, 0x0D) ^ gfMultiply(a3, 0x09);
        state[1][c] = gfMultiply(a0, 0x09) ^ gfMultiply(a1, 0x0E)
                    ^ gfMultiply(a2, 0x0B) ^ gfMultiply(a3, 0x0D);
        state[2][c] = gfMultiply(a0, 0x0D) ^ gfMultiply(a1, 0x09)
                    ^ gfMultiply(a2, 0x0E) ^ gfMultiply(a3, 0x0B);
        state[3][c] = gfMultiply(a0, 0x0B) ^ gfMultiply(a1, 0x0D)
                    ^ gfMultiply(a2, 0x09) ^ gfMultiply(a3, 0x0E);
    }
}

void encryptState(State& state, const ExpandedKey& expandedKey) {
    addRoundKey(state, expandedKey, 0);

    for (int round = 1; round < 14; ++round) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey, round);
    }

    // Final round deliberately omits MixColumns.
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey, 14);
}

void decryptState(State& state, const ExpandedKey& expandedKey) {
    // Decryption starts with the last encryption round key.
    addRoundKey(state, expandedKey, 14);

    // AES-256 has 13 middle rounds (13 down to 1).
    for (int round = 13; round >= 1; --round) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey, round);
        invMixColumns(state);
    }

    // Final inverse round: no InvMixColumns.
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey, 0);
}

int main() {
    const std::array<Byte, 32> key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };

    const std::array<Byte, 16> plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
    };

    const std::string expectedCiphertext = "8EA2B7CA516745BFEAFC49904B496089";
    const std::string expectedPlaintext  = "00112233445566778899AABBCCDDEEFF";

    const ExpandedKey expandedKey = keyExpansion(key);

    State state = bytesToState(plaintext);
    encryptState(state, expandedKey);
    const auto ciphertext = stateToBytes(state);

    auto toHex = [](const std::array<Byte, 16>& bytes) {
        std::string result;
        constexpr char digits[] = "0123456789ABCDEF";
        for (Byte b : bytes) {
            result.push_back(digits[b >> 4]);
            result.push_back(digits[b & 0x0F]);
        }
        return result;
    };

    const std::string actualCiphertext = toHex(ciphertext);
    std::cout << "Ciphertext: " << actualCiphertext << '\n';
    std::cout << "Encryption test: "
              << (actualCiphertext == expectedCiphertext ? "PASS" : "FAIL")
              << '\n';

    // Decrypt the ciphertext and check that we recover the original plaintext.
    State recoveredState = bytesToState(ciphertext);
    decryptState(recoveredState, expandedKey);
    const auto recoveredPlaintext = stateToBytes(recoveredState);
    const std::string actualPlaintext = toHex(recoveredPlaintext);

    std::cout << "Decrypted:  " << actualPlaintext << '\n';
    std::cout << "Decryption test: "
              << (actualPlaintext == expectedPlaintext ? "PASS" : "FAIL")
              << '\n';

    return (actualCiphertext == expectedCiphertext &&
            actualPlaintext == expectedPlaintext) ? 0 : 1;
}
