// =============================================================================
//  ecc.h  -  Elliptic Curve Cryptography on the NIST P-256 curve
// =============================================================================
//  WHAT IS AN ELLIPTIC CURVE?
//    The set of points (x, y) satisfying   y^2 = x^3 + a*x + b   (mod p).
//    P-256 uses a = -3 and a 256-bit prime p.
//
//  THE KEY IDEA ("point addition")
//    You can ADD two points on the curve and get a third point on the curve.
//    Adding a point G to itself k times gives   Q = k * G   ("scalar multiplication").
//        * Computing Q from k is FAST.
//        * Finding k from G and Q is believed to be IMPOSSIBLY HARD
//          (the "elliptic curve discrete logarithm problem").
//    That one-way property is what makes ECC secure.
//
//  NAMES USED IN THIS PROJECT
//    G   - the public "base point" everybody agrees on
//    n   - how many times you can add G before wrapping back to the start
//    d   - PRIVATE key (a random number between 1 and n-1)  -> keep secret!
//    Q   - PUBLIC key  = d * G                              -> share freely
//
//  WHAT THIS CLASS CAN DO
//    1. Point arithmetic          add(), dbl(), scalarMul()
//    2. ECDH key agreement        two people create a shared secret
//    3. ECDSA digital signatures  sign() / verify() (hashing with SHA-512)
// =============================================================================
#ifndef ECC_H
#define ECC_H

#include "bigint256.h"
#include <string>

// A point on the curve. "inf" = true means the special "point at infinity",
// which acts like zero for point addition (P + infinity = P).
struct Point {
    U256 x, y;
    bool inf;
    Point() : inf(true) {}                                   // default: infinity
    Point(const U256& X, const U256& Y) : x(X), y(Y), inf(false) {}
};

// An ECDSA signature is a pair of numbers (r, s).
struct Signature { U256 r, s; };

class ECC {
public:
    ECC();                                                   // loads the P-256 constants

    // --- the curve constants (read-only access) ---
    const U256&  p() const { return p_; }                    // prime modulus
    const U256&  n() const { return n_; }                    // order of G
    const Point& G() const { return G_; }                    // base point

    // --- point arithmetic ---
    bool  isOnCurve(const Point& P) const;                   // does P satisfy the equation?
    Point add(const Point& P, const Point& Q) const;         // P + Q
    Point dbl(const Point& P) const;                         // P + P  (doubling)
    Point negate(const Point& P) const;                      // -P  (mirror image over the x-axis)
    Point scalarMul(const U256& k, const Point& P) const;    // k * P

    // --- keys ---
    U256  randomScalar() const;                              // random private key in [1, n-1]
    Point publicKey(const U256& priv) const { return scalarMul(priv, G_); }

    // --- ECDH: shared secret from my private key and the other side's public key ---
    U256  ecdh(const U256& myPrivate, const Point& theirPublic) const;

    // --- ECDSA: digital signatures (the message is hashed with SHA-512) ---
    Signature sign(const U256& priv, const std::string& message) const;
    bool      verify(const Point& pub, const std::string& message, const Signature& sig) const;

private:
    // ---- Jacobian coordinates (a speed trick) ----
    // Adding points in normal (x, y) form needs a division (modular inverse) for
    // EVERY step, which is slow. Jacobian form stores a point as (X, Y, Z)
    // meaning x = X/Z^2 and y = Y/Z^3, so the division is postponed and done only
    // ONCE at the end. Z = 0 represents the point at infinity.
    struct Jac { U256 X, Y, Z; };
    Jac   toJac(const Point& P) const;                       // normal -> Jacobian
    Point toAffine(const Jac& J) const;                      // Jacobian -> normal (one division)
    Jac   jDouble(const Jac& P) const;
    Jac   jAdd(const Jac& P, const Jac& Q) const;

    // ---- Short names for arithmetic "mod p" so the formulas stay readable ----
    U256 fadd(const U256& a, const U256& b) const { return addMod(a, b, p_); }
    U256 fsub(const U256& a, const U256& b) const { return subMod(a, b, p_); }
    U256 fmul(const U256& a, const U256& b) const { return mulMod(a, b, p_); }

    U256 hashToNumber(const std::string& message) const;     // SHA-512 -> 256-bit number

    U256  p_, n_, b_;                                        // curve constants
    Point G_;                                                // base point
};

#endif
