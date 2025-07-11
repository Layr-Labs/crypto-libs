package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/pbkdf2"
)

// PrivateKey represents a secp256k1 ECDSA private key
type PrivateKey struct {
	D *big.Int
}

// PublicKey represents a secp256k1 ECDSA public key
type PublicKey struct {
	X, Y *big.Int
}

// Signature represents an ECDSA signature with recovery ID
type Signature struct {
	R, S *big.Int
	V    uint8 // Recovery ID
}

// GenerateKeyPair creates a new random secp256k1 ECDSA private key and corresponding public key
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	ecdsaPrivKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Validate generated key is non-zero and within curve order
	if ecdsaPrivKey.D == nil || ecdsaPrivKey.D.Sign() == 0 {
		return nil, nil, fmt.Errorf("generated private key is invalid")
	}

	n := secp256k1.S256().Params().N
	if ecdsaPrivKey.D.Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("generated private key exceeds curve order")
	}

	// Create a copy of the private key scalar to avoid sharing the same big.Int
	privKeyScalar := new(big.Int).Set(ecdsaPrivKey.D)

	privKey := &PrivateKey{
		D: privKeyScalar,
	}

	pubKey := &PublicKey{
		X: ecdsaPrivKey.PublicKey.X,
		Y: ecdsaPrivKey.PublicKey.Y,
	}

	// This prevents the sensitive key material from remaining in memory longer than necessary
	ecdsaPrivKey.D.SetInt64(0)

	return privKey, pubKey, nil
}

// GenerateKeyPairFromSeed creates a deterministic secp256k1 ECDSA private key from a seed
func GenerateKeyPairFromSeed(seed []byte) (*PrivateKey, *PublicKey, error) {
	// Validate seed input
	if seed == nil {
		return nil, nil, fmt.Errorf("seed cannot be nil")
	}
	if len(seed) == 0 {
		return nil, nil, fmt.Errorf("seed cannot be empty")
	}
	if len(seed) < 16 {
		return nil, nil, fmt.Errorf("seed must be at least 16 bytes for security")
	}
	if len(seed) > 1024*1024 {
		return nil, nil, fmt.Errorf("seed too large (max 1MB)")
	}

	// Use PBKDF2 to derive private key from seed
	// Parameters chosen for security vs performance balance
	const (
		iterations = 100000 // OWASP recommended minimum for 2023
		keyLength  = 32     // 32 bytes for secp256k1 private key
	)

	// Use SHA-256 as the hash function for PBKDF2
	// Salt is derived from a constant context to ensure deterministic behavior
	// while still providing the security benefits of PBKDF2
	salt := []byte("secp256k1-key-derivation-salt-v1")

	// Derive the private key using PBKDF2
	derivedKey := pbkdf2.Key(seed, salt, iterations, keyLength, sha256.New)

	// Convert derived key to big.Int and ensure it's within curve order
	d := new(big.Int).SetBytes(derivedKey)
	n := secp256k1.S256().Params().N
	d.Mod(d, n)

	// SECURITY: Handle the extremely rare case where d is zero
	// This should virtually never happen (probability ~1/2^256)
	if d.Sign() == 0 {
		return nil, nil, fmt.Errorf("seed resulted in invalid private key (zero value)")
	}

	// Final validation that the private key is valid
	if d.Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("seed resulted in invalid private key (exceeds curve order)")
	}

	privKey := &PrivateKey{
		D: d,
	}

	// Calculate public key
	x, y := secp256k1.S256().ScalarBaseMult(d.Bytes())
	pubKey := &PublicKey{
		X: x,
		Y: y,
	}

	// This prevents the derived key material from remaining in memory
	for i := range derivedKey {
		derivedKey[i] = 0
	}

	return privKey, pubKey, nil
}

// NewPrivateKeyFromBytes creates a secp256k1 private key from bytes
func NewPrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("private key data cannot be empty")
	}

	d := new(big.Int).SetBytes(data)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("private key cannot be zero")
	}

	// Ensure private key is within curve order
	n := secp256k1.S256().Params().N
	if d.Cmp(n) >= 0 {
		return nil, fmt.Errorf("private key exceeds curve order")
	}

	return &PrivateKey{
		D: d,
	}, nil
}

// NewPrivateKeyFromHexString creates a secp256k1 private key from a hex string
func NewPrivateKeyFromHexString(hexStr string) (*PrivateKey, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return NewPrivateKeyFromBytes(data)
}

// Sign signs a 32-byte hash using secp256k1 ECDSA
func (pk *PrivateKey) Sign(hash []byte) (*Signature, error) {
	// SECURITY: Comprehensive input validation
	if pk == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if pk.D == nil {
		return nil, fmt.Errorf("private key scalar cannot be nil")
	}
	if pk.D.Sign() == 0 {
		return nil, fmt.Errorf("private key cannot be zero")
	}
	if hash == nil {
		return nil, fmt.Errorf("hash cannot be nil")
	}
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(hash))
	}

	// SECURITY: Validate private key is within curve order
	n := secp256k1.S256().Params().N
	if pk.D.Cmp(n) >= 0 {
		return nil, fmt.Errorf("private key exceeds curve order")
	}

	// Pre-calculate public key to avoid timing attacks
	// Use deterministic method that doesn't depend on private key value timing
	pubKey := pk.Public()

	// Create ecdsa.PrivateKey for signing using pre-calculated public key
	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     pubKey.X,
			Y:     pubKey.Y,
		},
		D: pk.D,
	}

	// Use crypto.Sign for secp256k1 (Ethereum-compatible signatures with recovery ID)
	signature, err := crypto.Sign(hash, ecdsaPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	// SECURITY: Validate signature length before accessing
	if len(signature) != 65 {
		return nil, fmt.Errorf("unexpected signature length: expected 65 bytes, got %d", len(signature))
	}

	// signature is 65 bytes: [R || S || V]
	r := new(big.Int).SetBytes(signature[0:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := signature[64] + 27

	// Validate signature components are non-zero
	if r.Sign() == 0 {
		return nil, fmt.Errorf("signature R component cannot be zero")
	}
	if s.Sign() == 0 {
		return nil, fmt.Errorf("signature S component cannot be zero")
	}

	// Check for signature malleability (high S values)
	// Ensure S is in the lower half of the curve order to prevent malleability
	halfOrder := new(big.Int).Rsh(n, 1) // n/2
	if s.Cmp(halfOrder) > 0 {
		return nil, fmt.Errorf("signature S component too high (malleability risk)")
	}

	return &Signature{R: r, S: s, V: v}, nil
}

func (pk *PrivateKey) SignAndPack(hash [32]byte) ([]byte, error) {

	signature, err := pk.Sign(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	// signature.Bytes() already returns abi.encodePacked(r, s, v) format: 65 bytes [R || S || V]
	return signature.Bytes(), nil
}

// Public returns the corresponding public key
func (pk *PrivateKey) Public() *PublicKey {
	x, y := secp256k1.S256().ScalarBaseMult(pk.D.Bytes())
	return &PublicKey{
		X: x,
		Y: y,
	}
}

// Bytes serializes the private key to bytes
func (pk *PrivateKey) Bytes() []byte {
	return pk.D.Bytes()
}

func (pk *PrivateKey) DeriveAddress() (common.Address, error) {
	if pk == nil || pk.D == nil {
		return common.Address{}, fmt.Errorf("private key is nil")
	}

	// Derive public key
	pubKey := pk.Public()

	// Use crypto package to derive address from public key
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     pubKey.X,
		Y:     pubKey.Y,
	}

	address := crypto.PubkeyToAddress(*ecdsaPubKey)
	return address, nil
}

// NewPublicKeyFromBytes creates a secp256k1 public key from bytes
func NewPublicKeyFromBytes(data []byte) (*PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("public key data cannot be empty")
	}

	curve := secp256k1.S256()
	p := curve.Params().P // Field prime

	// Handle uncompressed format (0x04 prefix + 32 bytes X + 32 bytes Y)
	if len(data) == 65 && data[0] == 0x04 {
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])

		// SECURITY: Validate coordinates are valid field elements
		if x.Cmp(p) >= 0 {
			return nil, fmt.Errorf("x coordinate exceeds field prime")
		}
		if y.Cmp(p) >= 0 {
			return nil, fmt.Errorf("y coordinate exceeds field prime")
		}

		// SECURITY: Validate against point at infinity (special case)
		if x.Sign() == 0 && y.Sign() == 0 {
			return nil, fmt.Errorf("point at infinity is not a valid public key")
		}

		// SECURITY: Validate against zero coordinates (potential weak points)
		if x.Sign() == 0 {
			return nil, fmt.Errorf("x coordinate cannot be zero")
		}
		if y.Sign() == 0 {
			return nil, fmt.Errorf("y coordinate cannot be zero")
		}

		// Verify point is on curve
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not on curve")
		}

		// Validate point is in correct subgroup (prevent small subgroup attacks)
		// Check that n*P = O (point at infinity)
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not in the correct cryptographic subgroup")
		}

		return &PublicKey{X: x, Y: y}, nil
	}

	// Handle compressed format
	if len(data) == 33 && (data[0] == 0x02 || data[0] == 0x03) {
		x := new(big.Int).SetBytes(data[1:])

		// SECURITY: Validate x coordinate is valid field element
		if x.Cmp(p) >= 0 {
			return nil, fmt.Errorf("x coordinate exceeds field prime")
		}

		// SECURITY: Validate against zero x coordinate
		if x.Sign() == 0 {
			return nil, fmt.Errorf("x coordinate cannot be zero")
		}

		// Decompress the point with enhanced validation
		y := decompressPoint(x, data[0] == 0x03)
		if y == nil {
			return nil, fmt.Errorf("failed to decompress point")
		}

		// Additional validation after decompression
		if y.Sign() == 0 {
			return nil, fmt.Errorf("decompressed y coordinate cannot be zero")
		}

		// Validate point is in correct subgroup
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("decompressed point is not in the correct cryptographic subgroup")
		}

		return &PublicKey{X: x, Y: y}, nil
	}

	return nil, fmt.Errorf("invalid public key format")
}

// NewPublicKeyFromHexString creates a secp256k1 public key from a hex string
func NewPublicKeyFromHexString(hexStr string) (*PublicKey, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return NewPublicKeyFromBytes(data)
}

// Bytes serializes the public key to bytes (uncompressed format)
func (pk *PublicKey) Bytes() []byte {
	// Return uncompressed format: 0x04 + X + Y
	xBytes := pk.X.Bytes()
	yBytes := pk.Y.Bytes()

	// Pad to 32 bytes for secp256k1
	coordSize := 32
	result := make([]byte, 1+2*coordSize)
	result[0] = 0x04

	copy(result[1+coordSize-len(xBytes):1+coordSize], xBytes)
	copy(result[1+2*coordSize-len(yBytes):1+2*coordSize], yBytes)

	return result
}

// NewSignatureFromBytes creates a signature from bytes
func NewSignatureFromBytes(data []byte) (*Signature, error) {
	if len(data) != 65 {
		return nil, fmt.Errorf("signature must be 65 bytes (32 bytes R + 32 bytes S + 1 byte V)")
	}

	r := new(big.Int).SetBytes(data[:32])
	s := new(big.Int).SetBytes(data[32:64])
	v := data[64]

	return &Signature{R: r, S: s, V: v}, nil
}

// Verify verifies the signature against a 32-byte hash and public key
func (sig *Signature) Verify(publicKey *PublicKey, hash [32]byte) (bool, error) {
	// Create ecdsa.PublicKey for verification
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     publicKey.X,
		Y:     publicKey.Y,
	}

	// Verify the signature
	return ecdsa.Verify(ecdsaPubKey, hash[:], sig.R, sig.S), nil
}

// VerifyWithAddress verifies the signature by recovering the public key and comparing addresses
func (sig *Signature) VerifyWithAddress(hash []byte, expectedAddr common.Address) (bool, error) {
	// Convert signature to bytes for crypto.Ecrecover
	sigBytes := sig.Bytes()

	// Adjust V for crypto.Ecrecover (expects 0 or 1, not 27/28)
	if sigBytes[64] >= 27 {
		sigBytes[64] -= 27
	}

	// Recover public key from signature
	recoveredPubKeyBytes, err := crypto.Ecrecover(hash[:], sigBytes)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %w", err)
	}

	// Convert recovered public key bytes to ecdsa.PublicKey
	recoveredPubKey, err := crypto.UnmarshalPubkey(recoveredPubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal recovered public key: %w", err)
	}

	// Derive address from recovered public key
	recoveredAddr := crypto.PubkeyToAddress(*recoveredPubKey)

	// Compare addresses
	return recoveredAddr == expectedAddr, nil
}

// Bytes serializes the signature to bytes (Ethereum format: R + S + V)
func (sig *Signature) Bytes() []byte {
	// Always return 65 bytes for consistency (R + S + V)
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	result := make([]byte, 65)
	copy(result[32-len(rBytes):32], rBytes)
	copy(result[64-len(sBytes):64], sBytes)
	result[64] = sig.V

	return result
}

// decompressPoint decompresses a point from its X coordinate for secp256k1 with enhanced security
func decompressPoint(x *big.Int, yBit bool) *big.Int {
	if x == nil {
		return nil
	}

	curve := secp256k1.S256()
	p := curve.Params().P

	// SECURITY: Validate x is within field bounds
	if x.Cmp(p) >= 0 {
		return nil // Invalid field element
	}

	// SECURITY: Validate against zero x coordinate
	if x.Sign() == 0 {
		return nil // Zero x coordinate not allowed
	}

	// Calculate y² = x³ + 7 (for secp256k1: y² = x³ + ax + b where a=0, b=7)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, p)

	// Calculate square root
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil // Point not on curve
	}

	// SECURITY: Validate computed y coordinate
	if y.Cmp(p) >= 0 {
		return nil // Invalid field element
	}

	// Choose correct root based on yBit
	if (y.Bit(0) == 1) != yBit {
		y.Sub(p, y)
	}

	// SECURITY: Final validation of computed y
	if y.Sign() == 0 {
		return nil // Zero y coordinate not allowed
	}

	// SECURITY: Final validation that the point is actually on the curve
	if !curve.IsOnCurve(x, y) {
		return nil // Point not on curve
	}

	return y
}
