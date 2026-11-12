// =============================================================================
//  ecc.cpp  -  Elliptic Curve Cryptography on NIST P-256
// =============================================================================
#include "ecc.h"
#include "sha512.h"
#include <random>

// =============================================================================
//  SECTION 1: Curve constants
// =============================================================================
ECC::ECC() {
    // Official NIST P-256 (also called secp256r1) parameters, written in hex.
    // Curve:  y^2 = x^3 - 3x + b   (mod p)
    p_ = U256::fromHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    n_ = U256::fromHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    b_ = U256::fromHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

    // Base point G = (Gx, Gy)
    G_ = Point(U256::fromHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
               U256::fromHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
}

// Check whether a point really lies on the curve: is  y^2 == x^3 - 3x + b  ?
bool ECC::isOnCurve(const Point& P) const {
    if (P.inf) return true;
    U256 left   = fmul(P.y, P.y);                              // y^2
    U256 xCubed = fmul(fmul(P.x, P.x), P.x);                   // x^3
    U256 threeX = fmul(U256(3), P.x);                          // 3x
    U256 right  = fadd(fsub(xCubed, threeX), b_);              // x^3 - 3x + b
    return left == right;
}

// =============================================================================
//  SECTION 2: Point arithmetic
//  (the formulas below are the standard ones from the "Explicit-Formulas
//   Database"; we only describe what they do, not how they are derived)
// =============================================================================

// ---- conversions between normal and Jacobian form ----
ECC::Jac ECC::toJac(const Point& P) const {
    Jac J;                                                   // all zeros: Z = 0 -> infinity
    if (P.inf) return J;
    J.X = P.x;  J.Y = P.y;  J.Z = U256(1);                   // x = X/1, y = Y/1
    return J;
}

Point ECC::toAffine(const Jac& J) const {
    if (J.Z.isZero()) return Point();                        // infinity
    U256 zInv  = invMod(J.Z, p_);                            // the only division
    U256 zInv2 = fmul(zInv, zInv);                           // 1/Z^2
    U256 zInv3 = fmul(zInv2, zInv);                          // 1/Z^3
    return Point(fmul(J.X, zInv2), fmul(J.Y, zInv3));        // x = X/Z^2, y = Y/Z^3
}

// ---- DOUBLING: P + P ----
// Geometric idea: draw the tangent line at P, see where it hits the curve again,
// and mirror that point over the x-axis.
ECC::Jac ECC::jDouble(const Jac& P) const {
    if (P.Z.isZero() || P.Y.isZero()) return Jac();          // doubling infinity -> infinity

    U256 zSquared = fmul(P.Z, P.Z);
    U256 ySquared = fmul(P.Y, P.Y);
    U256 xy2      = fmul(P.X, ySquared);

    // slope-like term: 3 * (X - Z^2) * (X + Z^2)   (works because a = -3)
    U256 t     = fmul(fsub(P.X, zSquared), fadd(P.X, zSquared));
    U256 slope = fadd(fadd(t, t), t);

    U256 xy2_x2 = fadd(xy2, xy2);                            // 2 * xy2
    U256 xy2_x4 = fadd(xy2_x2, xy2_x2);                      // 4 * xy2
    U256 xy2_x8 = fadd(xy2_x4, xy2_x4);                      // 8 * xy2

    U256 y4      = fmul(ySquared, ySquared);                 // Y^4
    U256 y4_x2   = fadd(y4, y4);
    U256 y4_x4   = fadd(y4_x2, y4_x2);
    U256 y4_x8   = fadd(y4_x4, y4_x4);                       // 8 * Y^4

    Jac R;
    R.X = fsub(fmul(slope, slope), xy2_x8);                              // new X
    R.Y = fsub(fmul(slope, fsub(xy2_x4, R.X)), y4_x8);                   // new Y
    U256 yPlusZ = fadd(P.Y, P.Z);
    R.Z = fsub(fsub(fmul(yPlusZ, yPlusZ), ySquared), zSquared);          // new Z
    return R;
}

// ---- ADDITION: P + Q ----
// Geometric idea: draw the line through P and Q, see where it hits the curve
// a third time, and mirror that point over the x-axis.
ECC::Jac ECC::jAdd(const Jac& P, const Jac& Q) const {
    // Special cases: adding infinity ("zero") changes nothing.
    if (P.Z.isZero()) return Q;
    if (Q.Z.isZero()) return P;

    U256 z1sq = fmul(P.Z, P.Z);
    U256 z2sq = fmul(Q.Z, Q.Z);
    U256 u1   = fmul(P.X, z2sq);                             // bring both points to
    U256 u2   = fmul(Q.X, z1sq);                             // a common "scale"
    U256 s1   = fmul(fmul(P.Y, Q.Z), z2sq);
    U256 s2   = fmul(fmul(Q.Y, P.Z), z1sq);

    U256 h = fsub(u2, u1);                                   // difference in x
    U256 r = fsub(s2, s1);  r = fadd(r, r);                  // (twice) difference in y

    // Special cases: same x-coordinate
    if (h.isZero()) {
        if (r.isZero()) return jDouble(P);                   // P == Q  -> use doubling
        return Jac();                                        // P == -Q -> infinity
    }

    U256 h2 = fadd(h, h);
    U256 i  = fmul(h2, h2);
    U256 j  = fmul(h, i);
    U256 v  = fmul(u1, i);

    Jac R;
    R.X = fsub(fsub(fmul(r, r), j), fadd(v, v));                         // new X
    U256 s1j = fmul(s1, j);
    R.Y = fsub(fmul(r, fsub(v, R.X)), fadd(s1j, s1j));                   // new Y
    U256 zSum = fadd(P.Z, Q.Z);
    U256 zz   = fsub(fsub(fmul(zSum, zSum), z1sq), z2sq);
    R.Z = fmul(zz, h);                                                   // new Z
    return R;
}

// ---- public wrappers working with normal (x, y) points ----
Point ECC::add(const Point& P, const Point& Q) const { return toAffine(jAdd(toJac(P), toJac(Q))); }
Point ECC::dbl(const Point& P) const                 { return toAffine(jDouble(toJac(P))); }

// -P has the same x and the mirrored y:  (x, p - y)
Point ECC::negate(const Point& P) const {
    if (P.inf || P.y.isZero()) return P;
    U256 negY;
    subRaw(negY, p_, P.y);
    return Point(P.x, negY);
}

// ---- SCALAR MULTIPLICATION: k * P  ("double and add") ----
// Idea: write k in binary. Example k = 13 = 1101b.
//   Start with 0. For each bit from the left:
//     always DOUBLE the running total, and if the bit is 1 also ADD P.
//   13P = ((((P)*2 + 0)*2 + P)*2 + P)... -> only about 256 doublings and
//   at most 256 additions, instead of 2^256 additions.
// NOTE: this simple version is NOT "constant time", so it can leak the key
//       through timing. Real-world libraries use safer versions.
Point ECC::scalarMul(const U256& k, const Point& P) const {
    Jac total;                                               // starts at infinity (zero)
    Jac base = toJac(P);

    for (int i = k.bitLength() - 1; i >= 0; i--) {           // from the top bit down
        total = jDouble(total);                              // always double
        if (k.bit(i)) total = jAdd(total, base);             // add P when the bit is 1
    }
    return toAffine(total);
}

// =============================================================================
//  SECTION 3: Random private keys
// =============================================================================
U256 ECC::randomScalar() const {
    static std::random_device randomSource;                  // OS-provided randomness
    while (true) {
        uint8_t bytes[32];
        for (int i = 0; i < 32; i += 4) {
            uint32_t r = randomSource();
            for (int j = 0; j < 4; j++) bytes[i + j] = (uint8_t)(r >> (8 * j));
        }
        U256 k = U256::fromBytes(bytes);
        if (!k.isZero() && cmp(k, n_) < 0) return k;         // must be in [1, n-1], else retry
    }
}

// =============================================================================
//  SECTION 4: ECDH  (Elliptic Curve Diffie-Hellman)
//  Alice has (dA, QA), Bob has (dB, QB). They swap public keys QA, QB.
//    Alice computes  dA * QB = dA * (dB * G)
//    Bob   computes  dB * QA = dB * (dA * G)
//  Both equal (dA * dB) * G, so they now share a secret, though an
//  eavesdropper who only saw QA and QB cannot compute it.
// =============================================================================
U256 ECC::ecdh(const U256& myPrivate, const Point& theirPublic) const {
    Point shared = scalarMul(myPrivate, theirPublic);
    return shared.x;                                         // use the x-coordinate as the secret
}

// =============================================================================
//  SECTION 5: ECDSA  (Elliptic Curve Digital Signature Algorithm)
// =============================================================================

// Hash the message with SHA-512 and use the first 256 bits as a number "e".
U256 ECC::hashToNumber(const std::string& message) const {
    SHA512::Digest digest = SHA512::hash(message);
    U256 e = U256::fromBytes(digest.data());                 // first 32 bytes of the 64
    return reduce(e, n_);                                    // make sure e < n
}

// SIGNING (needs the PRIVATE key d):
//   1. e = hash(message)
//   2. pick a fresh random number k            (never reuse k!)
//   3. R = k * G,   r = x-coordinate of R (mod n)
//   4. s = k^-1 * (e + r*d)  (mod n)
//   5. the signature is the pair (r, s)
Signature ECC::sign(const U256& priv, const std::string& message) const {
    U256 e = hashToNumber(message);
    while (true) {
        U256  k = randomScalar();
        Point R = scalarMul(k, G_);
        U256  r = reduce(R.x, n_);
        if (r.isZero()) continue;                            // extremely unlikely: retry

        U256 kInverse = invMod(k, n_);
        U256 s = mulMod(kInverse, addMod(e, mulMod(r, priv, n_), n_), n_);
        if (s.isZero()) continue;                            // extremely unlikely: retry

        return Signature{r, s};
    }
}

// VERIFYING (needs only the PUBLIC key Q):
//   1. e = hash(message)
//   2. w = s^-1,  u1 = e*w,  u2 = r*w     (all mod n)
//   3. X = u1*G + u2*Q
//   4. signature is valid  <=>  x-coordinate of X (mod n) equals r
// Why it works: u1*G + u2*Q = (e + r*d)/s * G = k * G = R.
bool ECC::verify(const Point& pub, const std::string& message, const Signature& sig) const {
    // basic sanity checks on the inputs
    if (sig.r.isZero() || sig.s.isZero())          return false;
    if (cmp(sig.r, n_) >= 0 || cmp(sig.s, n_) >= 0) return false;
    if (pub.inf || !isOnCurve(pub))                return false;

    U256 e  = hashToNumber(message);
    U256 w  = invMod(sig.s, n_);
    U256 u1 = mulMod(e, w, n_);
    U256 u2 = mulMod(sig.r, w, n_);

    Point X = add(scalarMul(u1, G_), scalarMul(u2, pub));
    if (X.inf) return false;

    return reduce(X.x, n_) == sig.r;
}
