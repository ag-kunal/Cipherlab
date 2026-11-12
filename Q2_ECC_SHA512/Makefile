CXX      = g++
CXXFLAGS = -std=c++11 -O2 -Wall -Wextra
SRC      = main.cpp sha512.cpp ecc.cpp bigint256.cpp
TARGET   = ecc_sha512

all: $(TARGET)
$(TARGET): $(SRC) sha512.h ecc.h bigint256.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRC)
run: $(TARGET)
	./$(TARGET)
clean:
	rm -f $(TARGET)
