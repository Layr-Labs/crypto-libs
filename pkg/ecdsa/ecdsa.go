package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
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

	privKey := &PrivateKey{
		D: ecdsaPrivKey.D,
	}

	pubKey := &PublicKey{
		X: ecdsaPrivKey.PublicKey.X,
		Y: ecdsaPrivKey.PublicKey.Y,
	}

	return privKey, pubKey, nil
}

// GenerateKeyPairFromSeed creates a deterministic secp256k1 ECDSA private key from a seed
func GenerateKeyPairFromSeed(seed []byte) (*PrivateKey, *PublicKey, error) {
	// Use SHA-256 to derive private key from seed
	hash := sha256.Sum256(seed)

	// Convert hash to big.Int and ensure it's within curve order
	d := new(big.Int).SetBytes(hash[:])
	n := secp256k1.S256().Params().N
	d.Mod(d, n)

	// Ensure d is not zero
	if d.Sign() == 0 {
		d.SetInt64(1)
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
	// Create ecdsa.PrivateKey for signing
	x, y := secp256k1.S256().ScalarBaseMult(pk.D.Bytes())
	ecdsaPrivKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: secp256k1.S256(),
			X:     x,
			Y:     y,
		},
		D: pk.D,
	}

	// Use crypto.Sign for secp256k1 (Ethereum-compatible signatures with recovery ID)
	signature, err := crypto.Sign(hash[:], ecdsaPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}

	// signature is 65 bytes: [R || S || V]
	r := new(big.Int).SetBytes(signature[0:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := signature[64] + 27

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

	// Handle uncompressed format (0x04 prefix + 32 bytes X + 32 bytes Y)
	if len(data) == 65 && data[0] == 0x04 {
		x := new(big.Int).SetBytes(data[1:33])
		y := new(big.Int).SetBytes(data[33:65])

		// Verify point is on curve
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("point is not on curve")
		}

		return &PublicKey{X: x, Y: y}, nil
	}

	// Handle compressed format
	if len(data) == 33 && (data[0] == 0x02 || data[0] == 0x03) {
		x := new(big.Int).SetBytes(data[1:])

		// Decompress the point
		y := decompressPoint(x, data[0] == 0x03, curve)
		if y == nil {
			return nil, fmt.Errorf("failed to decompress point")
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

// decompressPoint decompresses a point from its X coordinate for secp256k1
func decompressPoint(x *big.Int, yBit bool, curve elliptic.Curve) *big.Int {
	p := curve.Params().P

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

	// Choose correct root based on yBit
	if (y.Bit(0) == 1) != yBit {
		y.Sub(p, y)
	}

	return y
}
