#include "../../../Q2_ECC_SHA512/sha512.h"
#include "../../../Q2_ECC_SHA512/ecc.h"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character.");
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::invalid_argument("Hex length must be even.");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1])));
    }
    return out;
}

std::string bytesToHexLower(const std::vector<uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

int countDifferentBits(const SHA512::Digest& a, const SHA512::Digest& b) {
    int count = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        uint8_t diff = a[i] ^ b[i];
        while (diff) {
            count += diff & 1;
            diff >>= 1;
        }
    }
    return count;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

U256 parseScalarHex(const std::string& hex, const ECC& ecc) {
    if (hex.empty() || hex.size() > 64) {
        throw std::invalid_argument("256-bit hex scalar must be 1..64 hex characters.");
    }
    for (char c : hex) hexNibble(c);
    U256 k = U256::fromHex(hex);
    if (k.isZero() || cmp(k, ecc.n()) >= 0) {
        throw std::invalid_argument("Private key scalar must be in [1, n-1].");
    }
    return k;
}

U256 parseCoordHex(const std::string& hex) {
    if (hex.empty() || hex.size() > 64) {
        throw std::invalid_argument("256-bit hex value must be 1..64 hex characters.");
    }
    for (char c : hex) hexNibble(c);
    return U256::fromHex(hex);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            throw std::invalid_argument("Usage: ecc_sha_cli <sha512|ecc_keygen|ecdsa_sign|ecdsa_verify|ecdh> ...");
        }
        std::string cmd = argv[1];

        if (cmd == "sha512") {
            if (argc < 4) throw std::invalid_argument("Usage: ecc_sha_cli sha512 <input_hex> <avalanche:0|1>");
            std::vector<uint8_t> data = hexToBytes(argv[2]);
            bool doAvalanche = std::string(argv[3]) == "1";

            SHA512::Digest digest = SHA512::hash(data.data(), data.size());
            std::string digestHex = SHA512::toHex(digest);

            size_t len = data.size();
            size_t paddedLen = ((len + 1 + 16 + 127) / 128) * 128;
            size_t zeroCount = paddedLen - len - 1 - 16;
            size_t blockCount = paddedLen / 128;

            std::cout << "{\"ok\":true,\"action\":\"sha512\""
                      << ",\"digest_hex\":\"" << digestHex << "\""
                      << ",\"input_bytes\":" << len
                      << ",\"padded_bytes\":" << paddedLen
                      << ",\"zero_pad_bytes\":" << zeroCount
                      << ",\"block_count\":" << blockCount
                      << ",\"bit_length\":" << (len * 8ULL);

            if (doAvalanche) {
                std::vector<uint8_t> mod = data;
                if (mod.empty()) {
                    mod.push_back(0x01);
                } else {
                    mod[0] ^= 0x01;
                }
                SHA512::Digest modDigest = SHA512::hash(mod.data(), mod.size());
                int diffBits = countDifferentBits(digest, modDigest);
                std::cout << ",\"avalanche\":{"
                          << "\"modified_hex\":\"" << bytesToHexLower(mod) << "\""
                          << ",\"modified_digest_hex\":\"" << SHA512::toHex(modDigest) << "\""
                          << ",\"diff_bits\":" << diffBits
                          << ",\"total_bits\":512"
                          << "}";
            }
            std::cout << "}\n";
            return 0;
        }

        ECC ecc;

        if (cmd == "ecc_keygen") {
            U256 priv = ecc.randomScalar();
            Point pub = ecc.publicKey(priv);
            std::cout << "{\"ok\":true,\"action\":\"ecc_keygen\""
                      << ",\"priv_hex\":\"" << priv.toHex() << "\""
                      << ",\"pub\":{\"x\":\"" << pub.x.toHex() << "\",\"y\":\"" << pub.y.toHex() << "\"}"
                      << ",\"on_curve\":" << (ecc.isOnCurve(pub) ? "true" : "false")
                      << "}\n";
            return 0;
        }

        if (cmd == "ecdsa_sign") {
            if (argc < 4) throw std::invalid_argument("Usage: ecc_sha_cli ecdsa_sign <priv_hex|auto> <msg_hex>");
            std::string privArg = argv[2];
            U256 priv = (privArg == "auto") ? ecc.randomScalar() : parseScalarHex(privArg, ecc);
            Point pub = ecc.publicKey(priv);

            std::vector<uint8_t> msgBytes = hexToBytes(argv[3]);
            std::string msg(reinterpret_cast<const char*>(msgBytes.data()), msgBytes.size());

            SHA512::Digest fullHash = SHA512::hash(msg);
            U256 eVal = reduce(U256::fromBytes(fullHash.data()), ecc.n());
            Signature sig = ecc.sign(priv, msg);
            bool selfVerify = ecc.verify(pub, msg, sig);

            std::cout << "{\"ok\":true,\"action\":\"ecdsa_sign\""
                      << ",\"priv_hex\":\"" << priv.toHex() << "\""
                      << ",\"pub\":{\"x\":\"" << pub.x.toHex() << "\",\"y\":\"" << pub.y.toHex() << "\"}"
                      << ",\"sha512_hex\":\"" << SHA512::toHex(fullHash) << "\""
                      << ",\"digest_e\":\"" << eVal.toHex() << "\""
                      << ",\"signature\":{\"r\":\"" << sig.r.toHex() << "\",\"s\":\"" << sig.s.toHex() << "\"}"
                      << ",\"valid\":" << (selfVerify ? "true" : "false")
                      << "}\n";
            return 0;
        }

        if (cmd == "ecdsa_verify") {
            if (argc < 7) throw std::invalid_argument("Usage: ecc_sha_cli ecdsa_verify <pub_x> <pub_y> <msg_hex> <r_hex> <s_hex>");
            Point pub(parseCoordHex(argv[2]), parseCoordHex(argv[3]));
            std::vector<uint8_t> msgBytes = hexToBytes(argv[4]);
            std::string msg(reinterpret_cast<const char*>(msgBytes.data()), msgBytes.size());
            Signature sig{parseCoordHex(argv[5]), parseCoordHex(argv[6])};

            bool onCurve = ecc.isOnCurve(pub);
            bool valid = ecc.verify(pub, msg, sig);
            std::string shaHex = SHA512::toHex(SHA512::hash(msg));

            std::cout << "{\"ok\":true,\"action\":\"ecdsa_verify\""
                      << ",\"on_curve\":" << (onCurve ? "true" : "false")
                      << ",\"sha512_hex\":\"" << shaHex << "\""
                      << ",\"valid\":" << (valid ? "true" : "false")
                      << "}\n";
            return 0;
        }

        if (cmd == "ecdh") {
            if (argc < 4) throw std::invalid_argument("Usage: ecc_sha_cli ecdh <alice_priv|auto> <bob_priv|auto>");
            U256 alicePriv = (std::string(argv[2]) == "auto") ? ecc.randomScalar() : parseScalarHex(argv[2], ecc);
            U256 bobPriv   = (std::string(argv[3]) == "auto") ? ecc.randomScalar() : parseScalarHex(argv[3], ecc);

            Point alicePub = ecc.publicKey(alicePriv);
            Point bobPub   = ecc.publicKey(bobPriv);

            U256 aliceSecret = ecc.ecdh(alicePriv, bobPub);
            U256 bobSecret   = ecc.ecdh(bobPriv, alicePub);
            bool matched = (aliceSecret == bobSecret);

            uint8_t secretBytes[32];
            aliceSecret.toBytes(secretBytes);
            std::string derivedKey = SHA512::toHex(SHA512::hash(secretBytes, 32)).substr(0, 64);

            std::cout << "{\"ok\":true,\"action\":\"ecdh\""
                      << ",\"alice_priv\":\"" << alicePriv.toHex() << "\""
                      << ",\"alice_pub\":{\"x\":\"" << alicePub.x.toHex() << "\",\"y\":\"" << alicePub.y.toHex() << "\"}"
                      << ",\"bob_priv\":\"" << bobPriv.toHex() << "\""
                      << ",\"bob_pub\":{\"x\":\"" << bobPub.x.toHex() << "\",\"y\":\"" << bobPub.y.toHex() << "\"}"
                      << ",\"alice_secret\":\"" << aliceSecret.toHex() << "\""
                      << ",\"bob_secret\":\"" << bobSecret.toHex() << "\""
                      << ",\"matched\":" << (matched ? "true" : "false")
                      << ",\"derived_aes_key\":\"" << derivedKey << "\""
                      << "}\n";
            return 0;
        }

        throw std::invalid_argument("Unknown command: " + cmd);
    } catch (const std::exception& ex) {
        std::cout << "{\"ok\":false,\"error\":\"" << jsonEscape(ex.what()) << "\"}\n";
        return 1;
    }
}
