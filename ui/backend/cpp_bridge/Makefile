CXX       := g++
CXXFLAGS17 := -std=c++17 -O2 -Wall -Wextra
CXXFLAGS11 := -std=c++11 -O2 -Wall -Wextra

BIN_DIR := bin
Q1_DIR  := ../../../Q1_AES256_RSA
Q2_DIR  := ../../../Q2_ECC_SHA512

all: $(BIN_DIR)/aes256_cli $(BIN_DIR)/rsa_cli $(BIN_DIR)/ecc_sha_cli $(BIN_DIR)/q2_runner

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BIN_DIR)/aes256_cli: aes256_cli.cpp $(Q1_DIR)/AES256.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS17) -o $@ aes256_cli.cpp

$(BIN_DIR)/rsa_cli: rsa_cli.cpp $(Q1_DIR)/RSA.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS17) -o $@ rsa_cli.cpp

$(BIN_DIR)/ecc_sha_cli: ecc_sha_cli.cpp $(Q2_DIR)/sha512.cpp $(Q2_DIR)/ecc.cpp $(Q2_DIR)/bigint256.cpp $(Q2_DIR)/sha512.h $(Q2_DIR)/ecc.h $(Q2_DIR)/bigint256.h | $(BIN_DIR)
	$(CXX) $(CXXFLAGS11) -o $@ ecc_sha_cli.cpp $(Q2_DIR)/sha512.cpp $(Q2_DIR)/ecc.cpp $(Q2_DIR)/bigint256.cpp

$(BIN_DIR)/q2_runner: $(Q2_DIR)/main.cpp $(Q2_DIR)/sha512.cpp $(Q2_DIR)/ecc.cpp $(Q2_DIR)/bigint256.cpp | $(BIN_DIR)
	$(CXX) $(CXXFLAGS11) -o $@ $(Q2_DIR)/main.cpp $(Q2_DIR)/sha512.cpp $(Q2_DIR)/ecc.cpp $(Q2_DIR)/bigint256.cpp

clean:
	rm -rf $(BIN_DIR)
