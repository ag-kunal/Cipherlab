#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define main assignment_main
#include "../../../Q1_AES256_RSA/RSA.cpp"
#undef main

namespace {

int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw invalid_argument("Invalid hex character.");
}

string hexToString(const string& hex) {
    if (hex.size() % 2 != 0) throw invalid_argument("Hex input length must be even.");
    string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int val = (hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1]);
        out.push_back(static_cast<char>(static_cast<unsigned char>(val)));
    }
    return out;
}

string stringToHex(const string& s) {
    static constexpr char digits[] = "0123456789ABCDEF";
    string out;
    out.reserve(s.size() * 2);
    for (unsigned char c : s) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0F]);
    }
    return out;
}

string jsonEscape(const string& s) {
    string out;
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

void printKeysJson(int64 p, int64 q, const RSAKeyPair& keys) {
    cout << "\"keys\":{\"p\":" << p
         << ",\"q\":" << q
         << ",\"n\":" << keys.n
         << ",\"phi\":" << keys.phi
         << ",\"e\":" << keys.e
         << ",\"d\":" << keys.d << "}";
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            throw invalid_argument("Usage: rsa_cli <encrypt_text|decrypt_text|encrypt_number|decrypt_number|kat> ...");
        }
        string cmd = argv[1];
        if (cmd == "kat") {
            return assignment_main();
        }

        if (argc < 6) {
            throw invalid_argument("Insufficient arguments.");
        }

        int64 p = stoll(argv[2]);
        int64 q = stoll(argv[3]);
        int64 e = stoll(argv[4]);
        RSAKeyPair keys = generateDemoKeys(p, q, e);

        if (cmd == "encrypt_text") {
            string text = hexToString(argv[5]);
            vector<int64> ct = encryptText(text, keys.e, keys.n);
            cout << "{\"ok\":true,\"action\":\"encrypt_text\",";
            printKeysJson(p, q, keys);
            cout << ",\"ciphertext_ints\":[";
            for (size_t i = 0; i < ct.size(); ++i) {
                if (i > 0) cout << ",";
                cout << ct[i];
            }
            cout << "],\"breakdown\":[";
            for (size_t i = 0; i < text.size(); ++i) {
                unsigned char ch = static_cast<unsigned char>(text[i]);
                if (i > 0) cout << ",";
                cout << "{\"index\":" << i
                     << ",\"byte\":" << static_cast<int>(ch)
                     << ",\"hex\":\"" << stringToHex(string(1, text[i])) << "\""
                     << ",\"cipher\":" << ct[i] << "}";
            }
            cout << "]}\n";
            return 0;
        }

        if (cmd == "decrypt_text") {
            string raw = argv[5];
            for (char& ch : raw) {
                if (ch == ',' || ch == ';') ch = ' ';
            }
            istringstream iss(raw);
            vector<int64> ct;
            int64 val;
            while (iss >> val) {
                ct.push_back(val);
            }
            if (ct.empty()) {
                throw invalid_argument("Provide at least one ciphertext integer.");
            }
            string recovered = decryptText(ct, keys.d, keys.n);
            cout << "{\"ok\":true,\"action\":\"decrypt_text\",";
            printKeysJson(p, q, keys);
            cout << ",\"recovered_hex\":\"" << stringToHex(recovered) << "\"}\n";
            return 0;
        }

        if (cmd == "encrypt_number") {
            int64 m = stoll(argv[5]);
            int64 c = encryptNumber(m, keys.e, keys.n);
            cout << "{\"ok\":true,\"action\":\"encrypt_number\",";
            printKeysJson(p, q, keys);
            cout << ",\"input_number\":" << m << ",\"result\":" << c << "}\n";
            return 0;
        }

        if (cmd == "decrypt_number") {
            int64 c = stoll(argv[5]);
            int64 m = decryptNumber(c, keys.d, keys.n);
            cout << "{\"ok\":true,\"action\":\"decrypt_number\",";
            printKeysJson(p, q, keys);
            cout << ",\"input_number\":" << c << ",\"result\":" << m << "}\n";
            return 0;
        }

        throw invalid_argument("Unknown command: " + cmd);
    } catch (const exception& ex) {
        cout << "{\"ok\":false,\"error\":\"" << jsonEscape(ex.what()) << "\"}\n";
        return 1;
    }
}
