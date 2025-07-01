package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

// PrivateKey represents an ECDSA private key
type PrivateKey struct {
	D     *big.Int
	curve elliptic.Curve
}

// PublicKey represents an ECDSA public key
type PublicKey struct {
	X, Y  *big.Int
	curve elliptic.Curve
}

// Signature represents an ECDSA signature with recovery ID
type Signature struct {
	R, S *big.Int
	V    uint8 // Recovery ID
}

// GenerateKeyPair creates a new random ECDSA private key and corresponding public key using secp256k1 (Ethereum compatible)
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	return GenerateKeyPairWithCurve(secp256k1.S256())
}

// GenerateKeyPairWithCurve creates a new random ECDSA private key and corresponding public key with specified curve
func GenerateKeyPairWithCurve(curve elliptic.Curve) (*PrivateKey, *PublicKey, error) {
	ecdsaPrivKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	privKey := &PrivateKey{
		D:     ecdsaPrivKey.D,
		curve: curve,
	}

	pubKey := &PublicKey{
		X:     ecdsaPrivKey.PublicKey.X,
		Y:     ecdsaPrivKey.PublicKey.Y,
		curve: curve,
	}

	return privKey, pubKey, nil
}

// GenerateKeyPairFromSeed creates a deterministic ECDSA private key from a seed using secp256k1
func GenerateKeyPairFromSeed(seed []byte) (*PrivateKey, *PublicKey, error) {
	return GenerateKeyPairFromSeedWithCurve(seed, secp256k1.S256())
}

// GenerateKeyPairFromSeedWithCurve creates a deterministic ECDSA private key from a seed with specified curve
func GenerateKeyPairFromSeedWithCurve(seed []byte, curve elliptic.Curve) (*PrivateKey, *PublicKey, error) {
	// Use SHA-256 to derive private key from seed
	hash := sha256.Sum256(seed)

	// Convert hash to big.Int and ensure it's within curve order
	d := new(big.Int).SetBytes(hash[:])
	n := curve.Params().N
	d.Mod(d, n)

	// Ensure d is not zero
	if d.Sign() == 0 {
		d.SetInt64(1)
	}

	privKey := &PrivateKey{
		D:     d,
		curve: curve,
	}

	// Calculate public key
	x, y := curve.ScalarBaseMult(d.Bytes())
	pubKey := &PublicKey{
		X:     x,
		Y:     y,
		curve: curve,
	}

	return privKey, pubKey, nil
}

// NewPrivateKeyFromBytes creates a private key from bytes using secp256k1
func NewPrivateKeyFromBytes(data []byte) (*PrivateKey, error) {
	return NewPrivateKeyFromBytesWithCurve(data, secp256k1.S256())
}

// NewPrivateKeyFromBytesWithCurve creates a private key from bytes with specified curve
func NewPrivateKeyFromBytesWithCurve(data []byte, curve elliptic.Curve) (*PrivateKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("private key data cannot be empty")
	}

	d := new(big.Int).SetBytes(data)
	if d.Sign() == 0 {
		return nil, fmt.Errorf("private key cannot be zero")
	}

	// Ensure private key is within curve order
	n := curve.Params().N
	if d.Cmp(n) >= 0 {
		return nil, fmt.Errorf("private key exceeds curve order")
	}

	return &PrivateKey{
		D:     d,
		curve: curve,
	}, nil
}

// NewPrivateKeyFromHexString creates a private key from a hex string using secp256k1
func NewPrivateKeyFromHexString(hexStr string) (*PrivateKey, error) {
	return NewPrivateKeyFromHexStringWithCurve(hexStr, secp256k1.S256())
}

// NewPrivateKeyFromHexStringWithCurve creates a private key from a hex string with specified curve
func NewPrivateKeyFromHexStringWithCurve(hexStr string, curve elliptic.Curve) (*PrivateKey, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return NewPrivateKeyFromBytesWithCurve(data, curve)
}

// Sign signs a message using ECDSA
func (pk *PrivateKey) Sign(message []byte) (*Signature, error) {
	// Hash the message
	hash := sha256.Sum256(message)

	// Create ecdsa.PrivateKey for signing
	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: pk.curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: pk.D,
	}

	// Calculate public key coordinates
	ecdsaPrivKey.PublicKey.X, ecdsaPrivKey.PublicKey.Y = pk.curve.ScalarBaseMult(pk.D.Bytes())

	// Use crypto.Sign for secp256k1 (Ethereum-compatible signatures with recovery ID)
	if pk.curve == secp256k1.S256() {
		signature, err := crypto.Sign(hash[:], ecdsaPrivKey)
		if err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}

		// signature is 65 bytes: [R || S || V]
		r := new(big.Int).SetBytes(signature[0:32])
		s := new(big.Int).SetBytes(signature[32:64])
		v := signature[64]

		return &Signature{R: r, S: s, V: v}, nil
	}

	// For other curves, use standard ECDSA signing (without recovery ID)
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// No recovery ID for non-secp256k1 curves
	return &Signature{R: r, S: s, V: 0}, nil
}

// Public returns the corresponding public key
func (pk *PrivateKey) Public() *PublicKey {
	x, y := pk.curve.ScalarBaseMult(pk.D.Bytes())
	return &PublicKey{
		X:     x,
		Y:     y,
		curve: pk.curve,
	}
}

// Bytes serializes the private key to bytes
func (pk *PrivateKey) Bytes() []byte {
	return pk.D.Bytes()
}

// NewPublicKeyFromBytes creates a public key from bytes using secp256k1
func NewPublicKeyFromBytes(data []byte) (*PublicKey, error) {
	return NewPublicKeyFromBytesWithCurve(data, secp256k1.S256())
}

// NewPublicKeyFromBytesWithCurve creates a public key from bytes with specified curve
func NewPublicKeyFromBytesWithCurve(data []byte, curve elliptic.Curve) (*PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("public key data cannot be empty")
	}

	// Handle uncompressed format (0x04 prefix + 32 bytes X + 32 bytes Y)
	if len(data) == 65 && data[0] == 0x04 {
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])

		// Verify point is on curve
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not on curve")
		}

		return &PublicKey{X: x, Y: y, curve: curve}, nil
	}

	// Handle compressed format
	if len(data) == 33 && (data[0] == 0x02 || data[0] == 0x03) {
		x := new(big.Int).SetBytes(data[1:])

		// Decompress the point
		y := decompressPoint(x, data[0] == 0x03, curve)
		if y == nil {
			return nil, fmt.Errorf("failed to decompress point")
		}

		return &PublicKey{X: x, Y: y, curve: curve}, nil
	}

	return nil, fmt.Errorf("invalid public key format")
}

// NewPublicKeyFromHexString creates a public key from a hex string using secp256k1
func NewPublicKeyFromHexString(hexStr string) (*PublicKey, error) {
	return NewPublicKeyFromHexStringWithCurve(hexStr, secp256k1.S256())
}

// NewPublicKeyFromHexStringWithCurve creates a public key from a hex string with specified curve
func NewPublicKeyFromHexStringWithCurve(hexStr string, curve elliptic.Curve) (*PublicKey, error) {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return NewPublicKeyFromBytesWithCurve(data, curve)
}

// Bytes serializes the public key to bytes (uncompressed format)
func (pk *PublicKey) Bytes() []byte {
	// Return uncompressed format: 0x04 + X + Y
	xBytes := pk.X.Bytes()
	yBytes := pk.Y.Bytes()

	// Pad to 32 bytes for P-256
	coordSize := (pk.curve.Params().BitSize + 7) / 8
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

// Verify verifies the signature against a message and public key
func (sig *Signature) Verify(publicKey *PublicKey, message []byte) (bool, error) {
	// Hash the message
	hash := sha256.Sum256(message)

	// Create ecdsa.PublicKey for verification
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: publicKey.curve,
		X:     publicKey.X,
		Y:     publicKey.Y,
	}

	// Verify the signature
	return ecdsa.Verify(ecdsaPubKey, hash[:], sig.R, sig.S), nil
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

// decompressPoint decompresses a point from its X coordinate
func decompressPoint(x *big.Int, yBit bool, curve elliptic.Curve) *big.Int {
	// This is a simplified implementation for P-256
	// For production use, should use curve-specific optimized implementations
	p := curve.Params().P

	// Calculate y² = x³ - 3x + b (for P-256)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Mul(x, big.NewInt(3))

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.Params().B)
	y2.Mod(y2, p)

	// Calculate square root
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil // Point not on curve
	}

	// Choose correct root based on yBit
	if (y.Bit(0) == 1) != yBit {
		y.Sub(p, y)
	}

	return y
}
