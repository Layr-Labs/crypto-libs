package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func TestGenerateKeyPair(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if privKey == nil {
		t.Fatal("Private key is nil")
	}

	if pubKey == nil {
		t.Fatal("Public key is nil")
	}

	// Test that public key matches private key
	derivedPubKey := privKey.Public()
	if derivedPubKey.X.Cmp(pubKey.X) != 0 || derivedPubKey.Y.Cmp(pubKey.Y) != 0 {
		t.Fatal("Derived public key does not match generated public key")
	}
}

func TestGenerateKeyPairFromSeed(t *testing.T) {
	seed := []byte("test seed for deterministic key generation")

	privKey1, pubKey1, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to generate key pair from seed: %v", err)
	}

	privKey2, pubKey2, err := GenerateKeyPairFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to generate second key pair from seed: %v", err)
	}

	// Keys generated from same seed should be identical
	if privKey1.D.Cmp(privKey2.D) != 0 {
		t.Fatal("Private keys from same seed are different")
	}

	if pubKey1.X.Cmp(pubKey2.X) != 0 || pubKey1.Y.Cmp(pubKey2.Y) != 0 {
		t.Fatal("Public keys from same seed are different")
	}
}

func TestPrivateKeyFromBytes(t *testing.T) {
	// Generate a key pair
	originalPrivKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate original key pair: %v", err)
	}

	// Serialize and deserialize
	privKeyBytes := originalPrivKey.Bytes()
	restoredPrivKey, err := NewPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to restore private key from bytes: %v", err)
	}

	if originalPrivKey.D.Cmp(restoredPrivKey.D) != 0 {
		t.Fatal("Restored private key does not match original")
	}
}

func TestPrivateKeyFromHexString(t *testing.T) {
	// Test with a known private key hex string
	hexKey := "c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3"

	privKey, err := NewPrivateKeyFromHexString(hexKey)
	if err != nil {
		t.Fatalf("Failed to create private key from hex: %v", err)
	}

	// Convert back to hex and compare
	restoredHex := hex.EncodeToString(privKey.Bytes())
	if restoredHex != hexKey {
		t.Fatalf("Expected hex %s, got %s", hexKey, restoredHex)
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	// Generate a key pair
	_, originalPubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate original key pair: %v", err)
	}

	// Serialize and deserialize
	pubKeyBytes := originalPubKey.Bytes()
	restoredPubKey, err := NewPublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		t.Fatalf("Failed to restore public key from bytes: %v", err)
	}

	if originalPubKey.X.Cmp(restoredPubKey.X) != 0 || originalPubKey.Y.Cmp(restoredPubKey.Y) != 0 {
		t.Fatal("Restored public key does not match original")
	}
}

func TestSignAndVerify(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Hello, ECDSA!")
	hash := sha256.Sum256(message)

	// Sign the message
	signature, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify the signature
	valid, err := signature.Verify(pubKey, hash)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	wrongHash := sha256.Sum256(wrongMessage)
	valid, err = signature.Verify(pubKey, wrongHash)
	if err != nil {
		t.Fatalf("Failed to verify signature with wrong message: %v", err)
	}

	if valid {
		t.Fatal("Signature should not verify with wrong message")
	}
}

func TestSignatureFromBytes(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Test message")
	hash := sha256.Sum256(message)

	// Sign the message
	originalSig, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Serialize and deserialize signature
	sigBytes := originalSig.Bytes()
	restoredSig, err := NewSignatureFromBytes(sigBytes)
	if err != nil {
		t.Fatalf("Failed to restore signature from bytes: %v", err)
	}

	// Verify the restored signature
	valid, err := restoredSig.Verify(pubKey, hash)
	if err != nil {
		t.Fatalf("Failed to verify restored signature: %v", err)
	}

	if !valid {
		t.Fatal("Restored signature verification failed")
	}
}

func TestSecp256k1SigningAndVerification(t *testing.T) {
	message := []byte("Test message for secp256k1")
	hash := sha256.Sum256(message)

	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	signature, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	valid, err := signature.Verify(pubKey, hash)
	if err != nil {
		t.Fatalf("Failed to verify: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}
}

func TestSchemeImplementsInterface(t *testing.T) {
	scheme := NewScheme()

	// Test that scheme implements signing.SigningScheme
	_ = signing.SigningScheme(scheme)

	// Test basic functionality through interface
	privKey, pubKey, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair through interface: %v", err)
	}

	message := []byte("Interface test message")
	signature, err := privKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign through interface: %v", err)
	}

	valid, err := signature.Verify(pubKey, message)
	if err != nil {
		t.Fatalf("Failed to verify through interface: %v", err)
	}

	if !valid {
		t.Fatal("Interface signature verification failed")
	}
}

func TestSchemeUnsupportedOperations(t *testing.T) {
	scheme := NewScheme()

	// Test EIP2333 (should be unsupported)
	_, _, err := scheme.GenerateKeyPairEIP2333([]byte("seed"), []uint32{0, 1, 2})
	if err != signing.ErrUnsupportedOperation {
		t.Fatalf("Expected ErrUnsupportedOperation for EIP2333, got: %v", err)
	}

	// Test signature aggregation (should be unsupported)
	_, err = scheme.AggregateSignatures([]signing.Signature{})
	if err != signing.ErrUnsupportedOperation {
		t.Fatalf("Expected ErrUnsupportedOperation for AggregateSignatures, got: %v", err)
	}

	// Test aggregate verify (should be unsupported)
	_, err = scheme.AggregateVerify([]signing.PublicKey{}, [][]byte{}, nil)
	if err != signing.ErrUnsupportedOperation {
		t.Fatalf("Expected ErrUnsupportedOperation for AggregateVerify, got: %v", err)
	}
}

func TestSchemeBatchVerify(t *testing.T) {
	scheme := NewScheme()

	// Generate multiple key pairs
	numKeys := 5
	privKeys := make([]signing.PrivateKey, numKeys)
	pubKeys := make([]signing.PublicKey, numKeys)
	signatures := make([]signing.Signature, numKeys)

	message := []byte("Batch verify test message")

	for i := 0; i < numKeys; i++ {
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		signature, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with key pair %d: %v", i, err)
		}

		privKeys[i] = privKey
		pubKeys[i] = pubKey
		signatures[i] = signature
	}

	// Test batch verification
	valid, err := scheme.BatchVerify(pubKeys, message, signatures)
	if err != nil {
		t.Fatalf("Batch verify failed: %v", err)
	}

	if !valid {
		t.Fatal("Batch verification should have succeeded")
	}

	// Test with invalid signature
	invalidSig, err := privKeys[0].Sign([]byte("different message"))
	if err != nil {
		t.Fatalf("Failed to create invalid signature: %v", err)
	}

	signatures[2] = invalidSig
	valid, err = scheme.BatchVerify(pubKeys, message, signatures)
	if err != nil {
		t.Fatalf("Batch verify with invalid signature failed: %v", err)
	}

	if valid {
		t.Fatal("Batch verification should have failed with invalid signature")
	}
}

func TestEthereumCompatibility(t *testing.T) {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Test message for Ethereum compatibility")
	hash := sha256.Sum256(message)

	// Sign the message
	signature, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify signature has recovery ID
	if signature.V == 0 && signature.R.Sign() == 0 && signature.S.Sign() == 0 {
		t.Fatal("Signature should have non-zero recovery ID")
	}

	// Verify signature is 65 bytes
	sigBytes := signature.Bytes()
	if len(sigBytes) != 65 {
		t.Fatalf("Expected 65-byte signature, got %d bytes", len(sigBytes))
	}

	// Verify format: [R || S || V]
	r := sigBytes[0:32]
	s := sigBytes[32:64]
	v := sigBytes[64]

	if len(r) != 32 || len(s) != 32 {
		t.Fatal("R and S should be 32 bytes each")
	}

	if v != signature.V {
		t.Fatalf("Expected V=%d, got V=%d", signature.V, v)
	}

	// Verify the signature
	valid, err := signature.Verify(pubKey, hash)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed")
	}
}

func TestKeyGeneration_EdgeCases(t *testing.T) {
	// Test empty private key data
	_, err := NewPrivateKeyFromBytes([]byte{})
	if err == nil {
		t.Fatal("Should fail with empty private key data")
	}

	// Test zero private key
	zeroKey := make([]byte, 32)
	_, err = NewPrivateKeyFromBytes(zeroKey)
	if err == nil {
		t.Fatal("Should fail with zero private key")
	}

	// Test empty public key data
	_, err = NewPublicKeyFromBytes([]byte{})
	if err == nil {
		t.Fatal("Should fail with empty public key data")
	}

	// Test invalid signature data
	_, err = NewSignatureFromBytes([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("Should fail with invalid signature data")
	}

	// Test invalid signature length (64 bytes instead of 65)
	invalidSig := make([]byte, 64)
	_, err = NewSignatureFromBytes(invalidSig)
	if err == nil {
		t.Fatal("Should fail with 64-byte signature (expected 65 bytes)")
	}
}

func TestConvertFromStandardECDSAPrivateKey(t *testing.T) {
	// Generate a standard secp256k1 crypto/ecdsa private key
	stdPrivKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate standard ECDSA private key: %v", err)
	}

	// Convert to module's PrivateKey using the private key scalar bytes
	privKeyBytes := stdPrivKey.D.Bytes()

	// Pad to 32 bytes if needed
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}

	modulePrivKey, err := NewPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("Failed to convert standard ECDSA private key to module private key: %v", err)
	}

	// Verify the conversion worked by comparing the private key scalars
	if stdPrivKey.D.Cmp(modulePrivKey.D) != 0 {
		t.Fatal("Converted private key scalar does not match original")
	}

	// Verify the public keys match
	stdPubKey := &stdPrivKey.PublicKey
	modulePubKey := modulePrivKey.Public()

	if stdPubKey.X.Cmp(modulePubKey.X) != 0 || stdPubKey.Y.Cmp(modulePubKey.Y) != 0 {
		t.Fatal("Converted public key does not match original")
	}

	// Test signing and verification works with the converted key
	message := []byte("Test message for converted key")
	hash := sha256.Sum256(message)
	signature, err := modulePrivKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign with converted private key: %v", err)
	}

	valid, err := signature.Verify(modulePubKey, hash)
	if err != nil {
		t.Fatalf("Failed to verify signature from converted key: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification failed for converted key")
	}
}

func TestVerifyWithAddress(t *testing.T) {
	// Generate key pair
	privKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Derive address from private key
	expectedAddr, err := privKey.DeriveAddress()
	if err != nil {
		t.Fatalf("Failed to derive address: %v", err)
	}

	// Sign a message
	message := []byte("Test message for address verification")
	hash := sha256.Sum256(message)
	signature, err := privKey.Sign(hash[:])
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Verify with correct address
	valid, err := signature.VerifyWithAddress(hash[:], expectedAddr)
	if err != nil {
		t.Fatalf("Failed to verify with address: %v", err)
	}

	if !valid {
		t.Fatal("Signature verification with correct address failed")
	}

	// Test with wrong address
	wrongAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	valid, err = signature.VerifyWithAddress(hash[:], wrongAddr)
	if err != nil {
		t.Fatalf("Failed to verify with wrong address: %v", err)
	}

	if valid {
		t.Fatal("Signature verification should have failed with wrong address")
	}
}
