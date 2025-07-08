package ecdsa

import (
	"crypto/sha256"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"
)

// Ensure Scheme implements the SigningScheme interface
var _ signing.SigningScheme = (*Scheme)(nil)

// Scheme implements the SigningScheme interface for secp256k1 ECDSA
type Scheme struct{}

// NewScheme creates a new secp256k1 ECDSA signing scheme
func NewScheme() *Scheme {
	return &Scheme{}
}

// GenerateKeyPair creates a new random private key and the corresponding public key
func (s *Scheme) GenerateKeyPair() (signing.PrivateKey, signing.PublicKey, error) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	return &privateKeyAdapter{privKey}, &publicKeyAdapter{pubKey}, nil
}

// GenerateKeyPairFromSeed creates a deterministic private key and the corresponding public key from a seed
func (s *Scheme) GenerateKeyPairFromSeed(seed []byte) (signing.PrivateKey, signing.PublicKey, error) {
	privKey, pubKey, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}

	return &privateKeyAdapter{privKey}, &publicKeyAdapter{pubKey}, nil
}

// GenerateKeyPairEIP2333 creates a deterministic private key and the corresponding public key using the EIP-2333 standard
// EIP-2333 is specific to BLS signatures and not applicable to ECDSA
func (s *Scheme) GenerateKeyPairEIP2333(seed []byte, path []uint32) (signing.PrivateKey, signing.PublicKey, error) {
	return nil, nil, signing.ErrUnsupportedOperation
}

// NewPrivateKeyFromBytes creates a private key from bytes
func (s *Scheme) NewPrivateKeyFromBytes(data []byte) (signing.PrivateKey, error) {
	privKey, err := NewPrivateKeyFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &privateKeyAdapter{privKey}, nil
}

// NewPrivateKeyFromHexString creates a private key from a hex string
func (s *Scheme) NewPrivateKeyFromHexString(hex string) (signing.PrivateKey, error) {
	privKey, err := NewPrivateKeyFromHexString(hex)
	if err != nil {
		return nil, err
	}
	return &privateKeyAdapter{privKey}, nil
}

// NewPublicKeyFromBytes creates a public key from bytes
func (s *Scheme) NewPublicKeyFromBytes(data []byte) (signing.PublicKey, error) {
	pubKey, err := NewPublicKeyFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &publicKeyAdapter{pubKey}, nil
}

// NewPublicKeyFromHexString creates a public key from a hex string
func (s *Scheme) NewPublicKeyFromHexString(hex string) (signing.PublicKey, error) {
	pubKey, err := NewPublicKeyFromHexString(hex)
	if err != nil {
		return nil, err
	}
	return &publicKeyAdapter{pubKey}, nil
}

// NewSignatureFromBytes creates a signature from bytes
func (s *Scheme) NewSignatureFromBytes(data []byte) (signing.Signature, error) {
	sig, err := NewSignatureFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &signatureAdapter{sig}, nil
}

// AggregateSignatures combines multiple signatures into a single signature
// ECDSA does not support signature aggregation
func (s *Scheme) AggregateSignatures(signatures []signing.Signature) (signing.Signature, error) {
	return nil, signing.ErrUnsupportedOperation
}

// BatchVerify verifies multiple signatures in a single batch operation
func (s *Scheme) BatchVerify(publicKeys []signing.PublicKey, message []byte, signatures []signing.Signature) (bool, error) {
	if len(publicKeys) != len(signatures) {
		return false, signing.ErrInvalidSignatureType
	}

	// Verify each signature individually
	for i, pubKey := range publicKeys {
		valid, err := signatures[i].Verify(pubKey, message)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// AggregateVerify verifies an aggregated signature against multiple public keys and multiple messages
// ECDSA does not support aggregated verification
func (s *Scheme) AggregateVerify(publicKeys []signing.PublicKey, messages [][]byte, aggSignature signing.Signature) (bool, error) {
	return false, signing.ErrUnsupportedOperation
}

// Adapter types for implementing the generic interfaces

// privateKeyAdapter adapts the ECDSA private key to the generic interface
type privateKeyAdapter struct {
	pk *PrivateKey
}

// Sign implements the signing.PrivateKey interface
func (a *privateKeyAdapter) Sign(message []byte) (signing.Signature, error) {
	// Hash the message
	hash := sha256.Sum256(message)

	sig, err := a.pk.Sign(hash[:])
	if err != nil {
		return nil, err
	}
	return &signatureAdapter{sig}, nil
}

// Public implements the signing.PrivateKey interface
func (a *privateKeyAdapter) Public() signing.PublicKey {
	return &publicKeyAdapter{a.pk.Public()}
}

// Bytes implements the signing.PrivateKey interface
func (a *privateKeyAdapter) Bytes() []byte {
	return a.pk.Bytes()
}

// publicKeyAdapter adapts the ECDSA public key to the generic interface
type publicKeyAdapter struct {
	pk *PublicKey
}

// Bytes implements the signing.PublicKey interface
func (a *publicKeyAdapter) Bytes() []byte {
	return a.pk.Bytes()
}

// signatureAdapter adapts the ECDSA signature to the generic interface
type signatureAdapter struct {
	sig *Signature
}

// Verify implements the signing.Signature interface
func (a *signatureAdapter) Verify(publicKey signing.PublicKey, message []byte) (bool, error) {
	ecdsaPubKey, ok := publicKey.(*publicKeyAdapter)
	if !ok {
		return false, signing.ErrInvalidPublicKeyType
	}

	// Hash the message
	hash := sha256.Sum256(message)

	return a.sig.Verify(ecdsaPubKey.pk, hash)
}

// Bytes implements the signing.Signature interface
func (a *signatureAdapter) Bytes() []byte {
	return a.sig.Bytes()
}
