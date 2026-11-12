#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define main assignment_main
#include "../../../Q1_AES256_RSA/AES256.cpp"
#undef main

namespace {

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument("Invalid hex character.");
}

std::vector<Byte> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex input length must be even.");
    }
    std::vector<Byte> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hexNibble(hex[i]);
        int lo = hexNibble(hex[i + 1]);
        out.push_back(static_cast<Byte>((hi << 4) | lo));
    }
    return out;
}

std::string bytesToHex(const std::vector<Byte>& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (Byte b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

std::string byteToHex(Byte b) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string s(2, '0');
    s[0] = digits[b >> 4];
    s[1] = digits[b & 0x0F];
    return s;
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

void printStateMatrix(const State& st) {
    std::cout << "[";
    for (int r = 0; r < 4; ++r) {
        if (r > 0) std::cout << ",";
        std::cout << "[";
        for (int c = 0; c < 4; ++c) {
            if (c > 0) std::cout << ",";
            std::cout << "\"" << byteToHex(st[r][c]) << "\"";
        }
        std::cout << "]";
    }
    std::cout << "]";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            throw std::invalid_argument("Usage: aes256_cli <encrypt|decrypt|kat> ...");
        }

        std::string cmd = argv[1];
        if (cmd == "kat") {
            int rc = assignment_main();
            return rc;
        }

        if (argc < 5) {
            throw std::invalid_argument("Usage: aes256_cli <encrypt|decrypt> <key_hex_64> <data_hex> <pkcs7|none>");
        }

        std::string keyHex = argv[2];
        std::string dataHex = argv[3];
        std::string padding = argv[4];

        std::vector<Byte> keyBytes = hexToBytes(keyHex);
        if (keyBytes.size() != 32) {
            throw std::invalid_argument("AES-256 requires a 32-byte (64-hex-character) key.");
        }
        std::array<Byte, 32> key{};
        for (size_t i = 0; i < 32; ++i) key[i] = keyBytes[i];

        std::vector<Byte> data = hexToBytes(dataHex);
        ExpandedKey expandedKey = keyExpansion(key);

        if (cmd == "encrypt") {
            if (padding == "pkcs7") {
                size_t padLen = 16 - (data.size() % 16);
                for (size_t i = 0; i < padLen; ++i) {
                    data.push_back(static_cast<Byte>(padLen));
                }
            } else if (padding == "none") {
                if (data.empty() || data.size() % 16 != 0) {
                    throw std::invalid_argument("Without padding, input must be a non-empty multiple of 16 bytes.");
                }
            } else {
                throw std::invalid_argument("Invalid padding mode; use pkcs7 or none.");
            }

            std::vector<Byte> out;
            out.reserve(data.size());
            std::cout << "{\"ok\":true,\"action\":\"encrypt\",\"padding\":\"" << padding << "\",\"blocks\":[";

            size_t numBlocks = data.size() / 16;
            for (size_t b = 0; b < numBlocks; ++b) {
                std::array<Byte, 16> blockIn{};
                for (size_t i = 0; i < 16; ++i) blockIn[i] = data[b * 16 + i];

                State inputState = bytesToState(blockIn);
                State workState = inputState;
                encryptState(workState, expandedKey);
                auto blockOut = stateToBytes(workState);

                for (Byte v : blockOut) out.push_back(v);

                if (b > 0) std::cout << ",";
                std::cout << "{\"index\":" << b
                          << ",\"input_hex\":\"" << bytesToHex(std::vector<Byte>(blockIn.begin(), blockIn.end())) << "\""
                          << ",\"output_hex\":\"" << bytesToHex(std::vector<Byte>(blockOut.begin(), blockOut.end())) << "\""
                          << ",\"input_state\":";
                printStateMatrix(inputState);
                std::cout << ",\"output_state\":";
                printStateMatrix(workState);
                std::cout << "}";
            }

            std::cout << "],\"output_hex\":\"" << bytesToHex(out) << "\"}\n";
            return 0;
        }

        if (cmd == "decrypt") {
            if (data.empty() || data.size() % 16 != 0) {
                throw std::invalid_argument("Ciphertext must be a non-empty multiple of 16 bytes (32 hex chars per block).");
            }

            std::vector<Byte> out;
            out.reserve(data.size());
            std::cout << "{\"ok\":true,\"action\":\"decrypt\",\"padding\":\"" << padding << "\",\"blocks\":[";

            size_t numBlocks = data.size() / 16;
            for (size_t b = 0; b < numBlocks; ++b) {
                std::array<Byte, 16> blockIn{};
                for (size_t i = 0; i < 16; ++i) blockIn[i] = data[b * 16 + i];

                State inputState = bytesToState(blockIn);
                State workState = inputState;
                decryptState(workState, expandedKey);
                auto blockOut = stateToBytes(workState);

                for (Byte v : blockOut) out.push_back(v);

                if (b > 0) std::cout << ",";
                std::cout << "{\"index\":" << b
                          << ",\"input_hex\":\"" << bytesToHex(std::vector<Byte>(blockIn.begin(), blockIn.end())) << "\""
                          << ",\"output_hex\":\"" << bytesToHex(std::vector<Byte>(blockOut.begin(), blockOut.end())) << "\""
                          << ",\"input_state\":";
                printStateMatrix(inputState);
                std::cout << ",\"output_state\":";
                printStateMatrix(workState);
                std::cout << "}";
            }

            bool paddingValid = true;
            if (padding == "pkcs7") {
                Byte padVal = out.back();
                if (padVal == 0 || padVal > 16 || padVal > out.size()) {
                    paddingValid = false;
                } else {
                    for (size_t i = out.size() - padVal; i < out.size(); ++i) {
                        if (out[i] != padVal) {
                            paddingValid = false;
                            break;
                        }
                    }
                    if (paddingValid) {
                        out.resize(out.size() - padVal);
                    }
                }
            } else if (padding != "none") {
                throw std::invalid_argument("Invalid padding mode; use pkcs7 or none.");
            }

            std::cout << "],\"padding_valid\":" << (paddingValid ? "true" : "false")
                      << ",\"output_hex\":\"" << bytesToHex(out) << "\"}\n";
            return 0;
        }

        throw std::invalid_argument("Unknown command: " + cmd);
    } catch (const std::exception& ex) {
        std::cout << "{\"ok\":false,\"error\":\"" << jsonEscape(ex.what()) << "\"}\n";
        return 1;
    }
}
