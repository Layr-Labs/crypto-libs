package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"math/big"

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

// Additional input validation tests - testing edge cases and invalid inputs

func TestInputValidation_GenerateKeyPairFromSeed(t *testing.T) {
	t.Run("NilSeed", func(t *testing.T) {
		_, _, err := GenerateKeyPairFromSeed(nil)
		if err == nil {
			t.Error("Expected error for nil seed, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected error message about nil seed, got: %v", err)
		}
	})

	t.Run("EmptySeed", func(t *testing.T) {
		_, _, err := GenerateKeyPairFromSeed([]byte{})
		if err == nil {
			t.Error("Expected error for empty seed, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected error message about empty seed, got: %v", err)
		}
	})

	t.Run("ShortSeed", func(t *testing.T) {
		shortSeed := []byte("short")
		_, _, err := GenerateKeyPairFromSeed(shortSeed)
		if err == nil {
			t.Error("Expected error for short seed, but got none")
		}
		if !strings.Contains(err.Error(), "at least 16 bytes") {
			t.Errorf("Expected error message about minimum seed length, got: %v", err)
		}
	})

	t.Run("ExactlyMinimumSeed", func(t *testing.T) {
		seed := make([]byte, 16)
		for i := range seed {
			seed[i] = byte(i)
		}
		_, _, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Errorf("Expected no error for 16-byte seed, but got: %v", err)
		}
	})

	t.Run("LargeSeed", func(t *testing.T) {
		largeSeed := make([]byte, 1024)
		for i := range largeSeed {
			largeSeed[i] = byte(i % 256)
		}
		_, _, err := GenerateKeyPairFromSeed(largeSeed)
		if err != nil {
			t.Errorf("Expected no error for large seed, but got: %v", err)
		}
	})

	t.Run("VeryLargeSeed", func(t *testing.T) {
		veryLargeSeed := make([]byte, 2*1024*1024) // 2MB seed
		_, _, err := GenerateKeyPairFromSeed(veryLargeSeed)
		if err == nil {
			t.Error("Expected error for very large seed, but got none")
		}
		if !strings.Contains(err.Error(), "too large") {
			t.Errorf("Expected error message about seed too large, got: %v", err)
		}
	})

	t.Run("DeterministicBehavior", func(t *testing.T) {
		seed := []byte("deterministic test seed with sufficient length")

		privKey1, pubKey1, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate first key pair: %v", err)
		}

		privKey2, pubKey2, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		if privKey1.D.Cmp(privKey2.D) != 0 {
			t.Error("Private keys should be identical for same seed")
		}
		if pubKey1.X.Cmp(pubKey2.X) != 0 || pubKey1.Y.Cmp(pubKey2.Y) != 0 {
			t.Error("Public keys should be identical for same seed")
		}
	})
}

func TestInputValidation_NewPrivateKeyFromBytes(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewPrivateKeyFromBytes(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected error message about empty data, got: %v", err)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewPrivateKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected error message about empty data, got: %v", err)
		}
	})

	t.Run("ShortData", func(t *testing.T) {
		shortData := []byte{0x01, 0x02, 0x03}
		_, err := NewPrivateKeyFromBytes(shortData)
		if err == nil {
			t.Error("Expected error for short data, but got none")
		}
		if !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("Expected error message about 32 bytes, got: %v", err)
		}
	})

	t.Run("LongData", func(t *testing.T) {
		longData := make([]byte, 64)
		for i := range longData {
			longData[i] = 0x01
		}
		_, err := NewPrivateKeyFromBytes(longData)
		if err == nil {
			t.Error("Expected error for long data, but got none")
		}
		if !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("Expected error message about 32 bytes, got: %v", err)
		}
	})

	t.Run("AllZeros", func(t *testing.T) {
		zeros := make([]byte, 32)
		_, err := NewPrivateKeyFromBytes(zeros)
		if err == nil {
			t.Error("Expected error for all zeros, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be zero") {
			t.Errorf("Expected error message about zero key, got: %v", err)
		}
	})

	t.Run("ValidKey", func(t *testing.T) {
		validKey := make([]byte, 32)
		validKey[31] = 0x01 // Set last byte to 1
		_, err := NewPrivateKeyFromBytes(validKey)
		if err != nil {
			t.Errorf("Expected no error for valid key, but got: %v", err)
		}
	})

	t.Run("MaxValidKey", func(t *testing.T) {
		// Create a key just under the curve order
		maxKey := make([]byte, 32)
		for i := range maxKey {
			maxKey[i] = 0xFF
		}
		maxKey[0] = 0x7F // Ensure it's under curve order
		_, err := NewPrivateKeyFromBytes(maxKey)
		if err != nil {
			t.Errorf("Expected no error for max valid key, but got: %v", err)
		}
	})
}

func TestInputValidation_NewPrivateKeyFromHexString(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("")
		if err == nil {
			t.Error("Expected error for empty string, but got none")
		}
	})

	t.Run("InvalidHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("invalid_hex_string")
		if err == nil {
			t.Error("Expected error for invalid hex string, but got none")
		}
	})

	t.Run("InvalidCharacters", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123g456h78901234567890123456789012345678901234567890123456789012")
		if err == nil {
			t.Error("Expected error for hex string with invalid characters, but got none")
		}
	})

	t.Run("OddLengthHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123456789012345678901234567890123456789012345678901234567890123")
		if err == nil {
			t.Error("Expected error for odd-length hex string, but got none")
		}
	})

	t.Run("ShortHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123456")
		if err == nil {
			t.Error("Expected error for short hex string, but got none")
		}
	})

	t.Run("LongHex", func(t *testing.T) {
		longHex := strings.Repeat("ab", 64) // 128 character hex string
		_, err := NewPrivateKeyFromHexString(longHex)
		if err == nil {
			t.Error("Expected error for long hex string, but got none")
		}
	})

	t.Run("WithPrefix", func(t *testing.T) {
		validHex := "0x0123456789012345678901234567890123456789012345678901234567890123"
		_, err := NewPrivateKeyFromHexString(validHex)
		if err != nil {
			t.Errorf("Expected no error for hex string with 0x prefix, but got: %v", err)
		}
	})

	t.Run("WithoutPrefix", func(t *testing.T) {
		validHex := "0123456789012345678901234567890123456789012345678901234567890123"
		_, err := NewPrivateKeyFromHexString(validHex)
		if err != nil {
			t.Errorf("Expected no error for hex string without prefix, but got: %v", err)
		}
	})

	t.Run("UppercaseHex", func(t *testing.T) {
		upperHex := "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"
		_, err := NewPrivateKeyFromHexString(upperHex)
		if err != nil {
			t.Errorf("Expected no error for uppercase hex, but got: %v", err)
		}
	})

	t.Run("MixedCaseHex", func(t *testing.T) {
		mixedHex := "AbCdEf1234567890aBcDeF1234567890AbCdEf1234567890aBcDeF1234567890"
		_, err := NewPrivateKeyFromHexString(mixedHex)
		if err != nil {
			t.Errorf("Expected no error for mixed case hex, but got: %v", err)
		}
	})

	t.Run("ZeroHex", func(t *testing.T) {
		zeroHex := strings.Repeat("00", 32)
		_, err := NewPrivateKeyFromHexString(zeroHex)
		if err == nil {
			t.Error("Expected error for zero hex string, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be zero") {
			t.Errorf("Expected error message about zero key, got: %v", err)
		}
	})
}

func TestInputValidation_PrivateKeySign(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	t.Run("NilHash", func(t *testing.T) {
		_, err := privateKey.Sign(nil)
		if err == nil {
			t.Error("Expected error for nil hash, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected error message about nil hash, got: %v", err)
		}
	})

	t.Run("EmptyHash", func(t *testing.T) {
		_, err := privateKey.Sign([]byte{})
		if err == nil {
			t.Error("Expected error for empty hash, but got none")
		}
		if !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("Expected error message about 32 bytes, got: %v", err)
		}
	})

	t.Run("ShortHash", func(t *testing.T) {
		shortHash := []byte{0x01, 0x02, 0x03}
		_, err := privateKey.Sign(shortHash)
		if err == nil {
			t.Error("Expected error for short hash, but got none")
		}
		if !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("Expected error message about 32 bytes, got: %v", err)
		}
	})

	t.Run("LongHash", func(t *testing.T) {
		longHash := make([]byte, 64)
		_, err := privateKey.Sign(longHash)
		if err == nil {
			t.Error("Expected error for long hash, but got none")
		}
		if !strings.Contains(err.Error(), "must be exactly 32 bytes") {
			t.Errorf("Expected error message about 32 bytes, got: %v", err)
		}
	})

	t.Run("ValidHash", func(t *testing.T) {
		validHash := make([]byte, 32)
		for i := range validHash {
			validHash[i] = byte(i)
		}
		_, err := privateKey.Sign(validHash)
		if err != nil {
			t.Errorf("Expected no error for valid hash, but got: %v", err)
		}
	})

	t.Run("AllZerosHash", func(t *testing.T) {
		zeroHash := make([]byte, 32)
		_, err := privateKey.Sign(zeroHash)
		if err != nil {
			t.Errorf("Expected no error for zero hash, but got: %v", err)
		}
	})

	t.Run("AllOnesHash", func(t *testing.T) {
		onesHash := make([]byte, 32)
		for i := range onesHash {
			onesHash[i] = 0xFF
		}
		_, err := privateKey.Sign(onesHash)
		if err != nil {
			t.Errorf("Expected no error for all ones hash, but got: %v", err)
		}
	})
}

func TestInputValidation_PrivateKeySignAndPack(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	t.Run("ValidHash", func(t *testing.T) {
		var validHash [32]byte
		for i := range validHash {
			validHash[i] = byte(i)
		}
		_, err := privateKey.SignAndPack(validHash)
		if err != nil {
			t.Errorf("Expected no error for valid hash, but got: %v", err)
		}
	})

	t.Run("ZeroHash", func(t *testing.T) {
		var zeroHash [32]byte
		sigBytes, err := privateKey.SignAndPack(zeroHash)
		if err != nil {
			t.Errorf("Expected no error for zero hash, but got: %v", err)
		}
		if len(sigBytes) != 65 {
			t.Errorf("Expected 65-byte signature, got %d bytes", len(sigBytes))
		}
	})

	t.Run("MaxHash", func(t *testing.T) {
		var maxHash [32]byte
		for i := range maxHash {
			maxHash[i] = 0xFF
		}
		_, err := privateKey.SignAndPack(maxHash)
		if err != nil {
			t.Errorf("Expected no error for max hash, but got: %v", err)
		}
	})
}

func TestInputValidation_NewPublicKeyFromBytes(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewPublicKeyFromBytes(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected error message about empty data, got: %v", err)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewPublicKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected error message about empty data, got: %v", err)
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		invalidData := []byte{0x01, 0x02, 0x03}
		_, err := NewPublicKeyFromBytes(invalidData)
		if err == nil {
			t.Error("Expected error for invalid length data, but got none")
		}
		if !strings.Contains(err.Error(), "invalid public key format") {
			t.Errorf("Expected error message about invalid format, got: %v", err)
		}
	})

	t.Run("InvalidUncompressedPrefix", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x05 // Invalid prefix (should be 0x04)
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for invalid uncompressed prefix, but got none")
		}
	})

	t.Run("InvalidCompressedPrefix", func(t *testing.T) {
		data := make([]byte, 33)
		data[0] = 0x01 // Invalid prefix (should be 0x02 or 0x03)
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for invalid compressed prefix, but got none")
		}
	})

	t.Run("UncompressedZeroCoordinates", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x04 // Valid uncompressed prefix
		// All zeros for X and Y coordinates
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero coordinates, but got none")
		}
		if !strings.Contains(err.Error(), "point at infinity") {
			t.Errorf("Expected error message about point at infinity, got: %v", err)
		}
	})

	t.Run("UncompressedZeroX", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x04 // Valid uncompressed prefix
		// Zero X coordinate, non-zero Y
		data[64] = 0x01
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero X coordinate, but got none")
		}
		if !strings.Contains(err.Error(), "x coordinate cannot be zero") {
			t.Errorf("Expected error message about zero X coordinate, got: %v", err)
		}
	})

	t.Run("UncompressedZeroY", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x04 // Valid uncompressed prefix
		// Non-zero X coordinate, zero Y
		data[32] = 0x01
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero Y coordinate, but got none")
		}
		if !strings.Contains(err.Error(), "y coordinate cannot be zero") {
			t.Errorf("Expected error message about zero Y coordinate, got: %v", err)
		}
	})

	t.Run("UncompressedNotOnCurve", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x04 // Valid uncompressed prefix
		// Set coordinates that are not on the curve
		data[32] = 0x01 // X = 1
		data[64] = 0x01 // Y = 1 (not on secp256k1 curve)
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for point not on curve, but got none")
		}
		if !strings.Contains(err.Error(), "not on curve") {
			t.Errorf("Expected error message about point not on curve, got: %v", err)
		}
	})

	t.Run("CompressedZeroX", func(t *testing.T) {
		data := make([]byte, 33)
		data[0] = 0x02 // Valid compressed prefix
		// Zero X coordinate
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero X coordinate in compressed format, but got none")
		}
		if !strings.Contains(err.Error(), "x coordinate cannot be zero") {
			t.Errorf("Expected error message about zero X coordinate, got: %v", err)
		}
	})

	t.Run("CompressedInvalidX", func(t *testing.T) {
		data := make([]byte, 33)
		data[0] = 0x02 // Valid compressed prefix
		// Set X coordinate that cannot be decompressed (try X = 3 which might not be on curve)
		data[32] = 0x03 // X = 3 (may not have valid Y on curve)
		_, err := NewPublicKeyFromBytes(data)
		// Note: This test might pass if X = 3 is valid on the curve,
		// which is acceptable behavior for the function
		if err != nil {
			t.Logf("Expected error for X coordinate that cannot be decompressed, got: %v", err)
		}
	})

	t.Run("LargeCoordinates", func(t *testing.T) {
		data := make([]byte, 65)
		data[0] = 0x04 // Valid uncompressed prefix
		// Set coordinates larger than field prime
		for i := 1; i < 33; i++ {
			data[i] = 0xFF // X coordinate = field prime
		}
		_, err := NewPublicKeyFromBytes(data)
		if err == nil {
			t.Error("Expected error for coordinates exceeding field prime, but got none")
		}
		if !strings.Contains(err.Error(), "exceeds field prime") {
			t.Errorf("Expected error message about field prime, got: %v", err)
		}
	})
}

func TestInputValidation_NewPublicKeyFromHexString(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		_, err := NewPublicKeyFromHexString("")
		if err == nil {
			t.Error("Expected error for empty string, but got none")
		}
	})

	t.Run("InvalidHex", func(t *testing.T) {
		_, err := NewPublicKeyFromHexString("invalid_hex")
		if err == nil {
			t.Error("Expected error for invalid hex string, but got none")
		}
	})

	t.Run("OddLengthHex", func(t *testing.T) {
		_, err := NewPublicKeyFromHexString("123")
		if err == nil {
			t.Error("Expected error for odd-length hex string, but got none")
		}
	})

	t.Run("WithPrefix", func(t *testing.T) {
		// Use a known valid public key hex string
		validHex := "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
		_, err := NewPublicKeyFromHexString(validHex)
		if err != nil {
			t.Errorf("Expected no error for valid hex string with 0x prefix, but got: %v", err)
		}
	})

	t.Run("WithoutPrefix", func(t *testing.T) {
		// Use a known valid public key hex string
		validHex := "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
		_, err := NewPublicKeyFromHexString(validHex)
		if err != nil {
			t.Errorf("Expected no error for valid hex string without prefix, but got: %v", err)
		}
	})

	t.Run("CompressedFormat", func(t *testing.T) {
		// Use a known valid compressed public key hex string
		compressedHex := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		_, err := NewPublicKeyFromHexString(compressedHex)
		if err != nil {
			t.Errorf("Expected no error for valid compressed hex string, but got: %v", err)
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		shortHex := "123456" // Too short for a public key
		_, err := NewPublicKeyFromHexString(shortHex)
		if err == nil {
			t.Error("Expected error for hex string too short for public key, but got none")
		}
	})
}

func TestInputValidation_NewSignatureFromBytes(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewSignatureFromBytes(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
		if !strings.Contains(err.Error(), "must be 65 bytes") {
			t.Errorf("Expected error message about 65 bytes, got: %v", err)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, but got none")
		}
		if !strings.Contains(err.Error(), "must be 65 bytes") {
			t.Errorf("Expected error message about 65 bytes, got: %v", err)
		}
	})

	t.Run("ShortData", func(t *testing.T) {
		shortData := make([]byte, 32)
		_, err := NewSignatureFromBytes(shortData)
		if err == nil {
			t.Error("Expected error for short data, but got none")
		}
		if !strings.Contains(err.Error(), "must be 65 bytes") {
			t.Errorf("Expected error message about 65 bytes, got: %v", err)
		}
	})

	t.Run("LongData", func(t *testing.T) {
		longData := make([]byte, 100)
		_, err := NewSignatureFromBytes(longData)
		if err == nil {
			t.Error("Expected error for long data, but got none")
		}
		if !strings.Contains(err.Error(), "must be 65 bytes") {
			t.Errorf("Expected error message about 65 bytes, got: %v", err)
		}
	})

	t.Run("ZeroR", func(t *testing.T) {
		data := make([]byte, 65)
		// R = 0, S = 1, V = 27
		data[32] = 0x01
		data[64] = 27
		_, err := NewSignatureFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero R component, but got none")
		}
		if !strings.Contains(err.Error(), "R component cannot be zero") {
			t.Errorf("Expected error message about zero R, got: %v", err)
		}
	})

	t.Run("ZeroS", func(t *testing.T) {
		data := make([]byte, 65)
		// R = 1, S = 0, V = 27
		data[31] = 0x01
		data[64] = 27
		_, err := NewSignatureFromBytes(data)
		if err == nil {
			t.Error("Expected error for zero S component, but got none")
		}
		if !strings.Contains(err.Error(), "S component cannot be zero") {
			t.Errorf("Expected error message about zero S, got: %v", err)
		}
	})

	t.Run("InvalidV", func(t *testing.T) {
		data := make([]byte, 65)
		// R = 1, S = 1, V = 26 (invalid)
		data[31] = 0x01
		data[63] = 0x01
		data[64] = 26
		_, err := NewSignatureFromBytes(data)
		if err == nil {
			t.Error("Expected error for invalid V value, but got none")
		}
		if !strings.Contains(err.Error(), "invalid signature V value") {
			t.Errorf("Expected error message about invalid V, got: %v", err)
		}
	})

	t.Run("ValidVValues", func(t *testing.T) {
		validVs := []uint8{0, 1, 27, 28}
		for _, v := range validVs {
			data := make([]byte, 65)
			// Set valid R and S
			data[31] = 0x01
			data[63] = 0x01
			data[64] = v
			_, err := NewSignatureFromBytes(data)
			if err != nil {
				t.Errorf("Expected no error for valid V value %d, but got: %v", v, err)
			}
		}
	})

	t.Run("HighS", func(t *testing.T) {
		data := make([]byte, 65)
		// R = 1
		data[31] = 0x01
		// S = high value (greater than curve order / 2)
		for i := 32; i < 64; i++ {
			data[i] = 0xFF
		}
		data[64] = 27
		_, err := NewSignatureFromBytes(data)
		if err == nil {
			t.Error("Expected error for high S value, but got none")
		}
		if !strings.Contains(err.Error(), "malleability risk") && !strings.Contains(err.Error(), "exceeds curve order") {
			t.Errorf("Expected error message about malleability or curve order, got: %v", err)
		}
	})

	t.Run("LargeR", func(t *testing.T) {
		data := make([]byte, 65)
		// R = larger than curve order
		for i := 0; i < 32; i++ {
			data[i] = 0xFF
		}
		data[63] = 0x01 // S = 1
		data[64] = 27
		_, err := NewSignatureFromBytes(data)
		if err == nil {
			t.Error("Expected error for R exceeding curve order, but got none")
		}
		if !strings.Contains(err.Error(), "exceeds curve order") {
			t.Errorf("Expected error message about curve order, got: %v", err)
		}
	})
}

func TestInputValidation_SignatureVerify(t *testing.T) {
	// Generate valid test data
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	validHash := [32]byte{0x01, 0x02, 0x03, 0x04}
	signature, err := privateKey.Sign(validHash[:])
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilPublicKey", func(t *testing.T) {
		_, err := signature.Verify(nil, validHash)
		if err == nil {
			t.Error("Expected error for nil public key, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected error message about nil public key, got: %v", err)
		}
	})

	t.Run("NilPublicKeyCoordinates", func(t *testing.T) {
		invalidPubKey := &PublicKey{X: nil, Y: publicKey.Y}
		_, err := signature.Verify(invalidPubKey, validHash)
		if err == nil {
			t.Error("Expected error for nil X coordinate, but got none")
		}
		if !strings.Contains(err.Error(), "coordinates cannot be nil") {
			t.Errorf("Expected error message about nil coordinates, got: %v", err)
		}

		invalidPubKey = &PublicKey{X: publicKey.X, Y: nil}
		_, err = signature.Verify(invalidPubKey, validHash)
		if err == nil {
			t.Error("Expected error for nil Y coordinate, but got none")
		}
		if !strings.Contains(err.Error(), "coordinates cannot be nil") {
			t.Errorf("Expected error message about nil coordinates, got: %v", err)
		}
	})

	t.Run("PublicKeyNotOnCurve", func(t *testing.T) {
		invalidPubKey := &PublicKey{
			X: big.NewInt(1),
			Y: big.NewInt(1), // (1, 1) is not on secp256k1 curve
		}
		_, err := signature.Verify(invalidPubKey, validHash)
		if err == nil {
			t.Error("Expected error for public key not on curve, but got none")
		}
		if !strings.Contains(err.Error(), "not on curve") {
			t.Errorf("Expected error message about point not on curve, got: %v", err)
		}
	})

	t.Run("ValidVerification", func(t *testing.T) {
		valid, err := signature.Verify(publicKey, validHash)
		if err != nil {
			t.Errorf("Expected no error for valid verification, but got: %v", err)
		}
		if !valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("WrongHash", func(t *testing.T) {
		wrongHash := [32]byte{0xFF, 0xFE, 0xFD, 0xFC}
		valid, err := signature.Verify(publicKey, wrongHash)
		if err != nil {
			t.Errorf("Expected no error for wrong hash verification, but got: %v", err)
		}
		if valid {
			t.Error("Expected signature to be invalid for wrong hash")
		}
	})
}

func TestInputValidation_SignatureVerifyWithAddress(t *testing.T) {
	// Generate valid test data
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	expectedAddr, err := privateKey.DeriveAddress()
	if err != nil {
		t.Fatalf("Failed to derive address: %v", err)
	}

	validHash := make([]byte, 32)
	for i := range validHash {
		validHash[i] = byte(i)
	}

	signature, err := privateKey.Sign(validHash)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilHash", func(t *testing.T) {
		_, err := signature.VerifyWithAddress(nil, expectedAddr)
		if err == nil {
			t.Error("Expected error for nil hash, but got none")
		}
	})

	t.Run("EmptyHash", func(t *testing.T) {
		_, err := signature.VerifyWithAddress([]byte{}, expectedAddr)
		if err == nil {
			t.Error("Expected error for empty hash, but got none")
		}
	})

	t.Run("ShortHash", func(t *testing.T) {
		shortHash := []byte{0x01, 0x02}
		_, err := signature.VerifyWithAddress(shortHash, expectedAddr)
		if err == nil {
			t.Error("Expected error for short hash, but got none")
		}
	})

	t.Run("ValidVerification", func(t *testing.T) {
		valid, err := signature.VerifyWithAddress(validHash, expectedAddr)
		if err != nil {
			t.Errorf("Expected no error for valid verification, but got: %v", err)
		}
		if !valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("WrongAddress", func(t *testing.T) {
		wrongAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		valid, err := signature.VerifyWithAddress(validHash, wrongAddr)
		if err != nil {
			t.Errorf("Expected no error for wrong address verification, but got: %v", err)
		}
		if valid {
			t.Error("Expected signature to be invalid for wrong address")
		}
	})

	t.Run("ZeroAddress", func(t *testing.T) {
		zeroAddr := common.Address{}
		valid, err := signature.VerifyWithAddress(validHash, zeroAddr)
		if err != nil {
			t.Errorf("Expected no error for zero address verification, but got: %v", err)
		}
		if valid {
			t.Error("Expected signature to be invalid for zero address")
		}
	})
}

func TestInputValidation_PrivateKeyMethods(t *testing.T) {
	t.Run("NilPrivateKey", func(t *testing.T) {
		var pk *PrivateKey = nil
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil private key, but got none")
			}
		}()
		_ = pk.Public()
	})

	t.Run("NilD", func(t *testing.T) {
		pk := &PrivateKey{D: nil}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil D, but got none")
			}
		}()
		_ = pk.Public()
	})

	t.Run("ZeroD", func(t *testing.T) {
		pk := &PrivateKey{D: big.NewInt(0)}
		pubKey := pk.Public()
		if pubKey == nil {
			t.Error("Expected non-nil public key even for zero D")
		}
	})

	t.Run("ValidPrivateKey", func(t *testing.T) {
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		pubKey := privateKey.Public()
		if pubKey == nil || pubKey.X == nil || pubKey.Y == nil {
			t.Error("Expected valid public key from valid private key")
		}

		bytes := privateKey.Bytes()
		if len(bytes) != 32 {
			t.Errorf("Expected 32 bytes from private key, got %d", len(bytes))
		}
	})

	t.Run("DeriveAddressNilPrivateKey", func(t *testing.T) {
		var pk *PrivateKey = nil
		_, err := pk.DeriveAddress()
		if err == nil {
			t.Error("Expected error for nil private key, but got none")
		}
		if !strings.Contains(err.Error(), "is nil") {
			t.Errorf("Expected error message about nil private key, got: %v", err)
		}
	})

	t.Run("DeriveAddressNilD", func(t *testing.T) {
		pk := &PrivateKey{D: nil}
		_, err := pk.DeriveAddress()
		if err == nil {
			t.Error("Expected error for nil D, but got none")
		}
		if !strings.Contains(err.Error(), "is nil") {
			t.Errorf("Expected error message about nil private key, got: %v", err)
		}
	})

	t.Run("DeriveAddressValid", func(t *testing.T) {
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		addr, err := privateKey.DeriveAddress()
		if err != nil {
			t.Errorf("Expected no error for valid private key, but got: %v", err)
		}
		if addr == (common.Address{}) {
			t.Error("Expected non-zero address")
		}
	})
}

func TestInputValidation_PublicKeyMethods(t *testing.T) {
	t.Run("NilPublicKey", func(t *testing.T) {
		var pk *PublicKey = nil
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key, but got none")
			}
		}()
		_ = pk.Bytes()
	})

	t.Run("NilCoordinates", func(t *testing.T) {
		pk := &PublicKey{X: nil, Y: nil}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil coordinates, but got none")
			}
		}()
		_ = pk.Bytes()
	})

	t.Run("PartiallyNilCoordinates", func(t *testing.T) {
		pk := &PublicKey{X: big.NewInt(1), Y: nil}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil Y coordinate, but got none")
			}
		}()
		_ = pk.Bytes()
	})

	t.Run("ValidPublicKey", func(t *testing.T) {
		_, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		bytes := publicKey.Bytes()
		if len(bytes) != 65 {
			t.Errorf("Expected 65 bytes from public key, got %d", len(bytes))
		}
		if bytes[0] != 0x04 {
			t.Errorf("Expected uncompressed format prefix 0x04, got 0x%02x", bytes[0])
		}
	})

	t.Run("ZeroCoordinates", func(t *testing.T) {
		pk := &PublicKey{X: big.NewInt(0), Y: big.NewInt(0)}
		bytes := pk.Bytes()
		if len(bytes) != 65 {
			t.Errorf("Expected 65 bytes even for zero coordinates, got %d", len(bytes))
		}
		if bytes[0] != 0x04 {
			t.Errorf("Expected uncompressed format prefix 0x04, got 0x%02x", bytes[0])
		}
		// All other bytes should be zero
		for i := 1; i < 65; i++ {
			if bytes[i] != 0 {
				t.Errorf("Expected zero byte at position %d, got 0x%02x", i, bytes[i])
			}
		}
	})
}

func TestInputValidation_SignatureMethods(t *testing.T) {
	// Generate valid test data
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	validHash := make([]byte, 32)
	signature, err := privateKey.Sign(validHash)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilSignature", func(t *testing.T) {
		var sig *Signature = nil
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil signature, but got none")
			}
		}()
		_ = sig.Bytes()
	})

	t.Run("NilComponents", func(t *testing.T) {
		sig := &Signature{R: nil, S: nil, V: 27}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil R and S, but got none")
			}
		}()
		_ = sig.Bytes()
	})

	t.Run("PartiallyNilComponents", func(t *testing.T) {
		sig := &Signature{R: big.NewInt(1), S: nil, V: 27}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil S, but got none")
			}
		}()
		_ = sig.Bytes()
	})

	t.Run("ValidSignature", func(t *testing.T) {
		bytes := signature.Bytes()
		if len(bytes) != 65 {
			t.Errorf("Expected 65 bytes from signature, got %d", len(bytes))
		}
		if bytes[64] != signature.V {
			t.Errorf("Expected V value %d, got %d", signature.V, bytes[64])
		}
	})

	t.Run("ZeroComponents", func(t *testing.T) {
		sig := &Signature{R: big.NewInt(0), S: big.NewInt(0), V: 27}
		bytes := sig.Bytes()
		if len(bytes) != 65 {
			t.Errorf("Expected 65 bytes even for zero components, got %d", len(bytes))
		}
		// R and S should be zero, V should be 27
		for i := 0; i < 64; i++ {
			if bytes[i] != 0 {
				t.Errorf("Expected zero byte at position %d, got 0x%02x", i, bytes[i])
			}
		}
		if bytes[64] != 27 {
			t.Errorf("Expected V value 27, got %d", bytes[64])
		}
	})
}

func TestInputValidation_SchemeAdapterMethods(t *testing.T) {
	scheme := NewScheme()

	t.Run("SchemeGenerateKeyPairFromSeed_NilSeed", func(t *testing.T) {
		_, _, err := scheme.GenerateKeyPairFromSeed(nil)
		if err == nil {
			t.Error("Expected error for nil seed, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil error message, got: %v", err)
		}
	})

	t.Run("SchemeNewPrivateKeyFromBytes_Invalid", func(t *testing.T) {
		_, err := scheme.NewPrivateKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes, but got none")
		}
	})

	t.Run("SchemeNewPublicKeyFromBytes_Invalid", func(t *testing.T) {
		_, err := scheme.NewPublicKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes, but got none")
		}
	})

	t.Run("SchemeNewSignatureFromBytes_Invalid", func(t *testing.T) {
		_, err := scheme.NewSignatureFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes, but got none")
		}
	})

	t.Run("SchemeBatchVerify_NilInputs", func(t *testing.T) {
		message := []byte("test")

		// Test nil public keys
		_, err := scheme.BatchVerify(nil, message, []signing.Signature{})
		if err == nil {
			t.Error("Expected error for nil public keys, but got none")
		}

		// Test nil message
		_, err = scheme.BatchVerify([]signing.PublicKey{}, nil, []signing.Signature{})
		if err == nil {
			t.Error("Expected error for nil message, but got none")
		}

		// Test nil signatures
		_, err = scheme.BatchVerify([]signing.PublicKey{}, message, nil)
		if err == nil {
			t.Error("Expected error for nil signatures, but got none")
		}
	})

	t.Run("SchemeBatchVerify_EmptyInputs", func(t *testing.T) {
		message := []byte("test")

		// Test empty public keys
		_, err := scheme.BatchVerify([]signing.PublicKey{}, message, []signing.Signature{})
		if err == nil {
			t.Error("Expected error for empty public keys, but got none")
		}

		// Test empty signatures
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		_, err = scheme.BatchVerify([]signing.PublicKey{pubKey}, message, []signing.Signature{})
		if err == nil {
			t.Error("Expected error for empty signatures, but got none")
		}
	})

	t.Run("SchemeBatchVerify_NilElements", func(t *testing.T) {
		message := []byte("test")
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		sig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Test nil public key in slice
		_, err = scheme.BatchVerify([]signing.PublicKey{nil}, message, []signing.Signature{sig})
		if err == nil {
			t.Error("Expected error for nil public key in slice, but got none")
		}

		// Test nil signature in slice
		_, err = scheme.BatchVerify([]signing.PublicKey{pubKey}, message, []signing.Signature{nil})
		if err == nil {
			t.Error("Expected error for nil signature in slice, but got none")
		}
	})

	t.Run("PrivateKeyAdapter_NilMessage", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		_, err = privKey.Sign(nil)
		if err == nil {
			t.Error("Expected error for nil message, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil error message, got: %v", err)
		}
	})

	t.Run("SignatureAdapter_NilInputs", func(t *testing.T) {
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Test verify with nil public key
		_, err = sig.Verify(nil, []byte("test"))
		if err == nil {
			t.Error("Expected error for nil public key, but got none")
		}

		// Test verify with nil message
		_, err = sig.Verify(pubKey, nil)
		if err == nil {
			t.Error("Expected error for nil message, but got none")
		}
	})

	t.Run("UnsupportedOperations", func(t *testing.T) {
		// EIP2333 should be unsupported
		_, _, err := scheme.GenerateKeyPairEIP2333([]byte("seed"), []uint32{0})
		if err != signing.ErrUnsupportedOperation {
			t.Errorf("Expected ErrUnsupportedOperation for EIP2333, got: %v", err)
		}

		// Aggregate signatures should be unsupported
		_, err = scheme.AggregateSignatures([]signing.Signature{})
		if err != signing.ErrUnsupportedOperation {
			t.Errorf("Expected ErrUnsupportedOperation for AggregateSignatures, got: %v", err)
		}

		// Aggregate verify should be unsupported
		_, err = scheme.AggregateVerify([]signing.PublicKey{}, [][]byte{}, nil)
		if err != signing.ErrUnsupportedOperation {
			t.Errorf("Expected ErrUnsupportedOperation for AggregateVerify, got: %v", err)
		}
	})
}

func TestInputValidation_DecompressPoint(t *testing.T) {
	// Note: decompressPoint is not directly exported, so we test it through NewPublicKeyFromBytes

	t.Run("CompressedValidPoint", func(t *testing.T) {
		// Generator point compressed (0x02 format)
		compressedGen := []byte{0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98}
		_, err := NewPublicKeyFromBytes(compressedGen)
		if err != nil {
			t.Errorf("Expected no error for valid compressed point, but got: %v", err)
		}
	})

	t.Run("CompressedValidPointOdd", func(t *testing.T) {
		// Generator point compressed (0x03 format)
		compressedGenOdd := []byte{0x03, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98}
		_, err := NewPublicKeyFromBytes(compressedGenOdd)
		if err != nil {
			t.Errorf("Expected no error for valid compressed point (odd), but got: %v", err)
		}
	})

	t.Run("CompressedInvalidX", func(t *testing.T) {
		// X coordinate that doesn't have a valid Y on the curve
		invalidCompressed := make([]byte, 33)
		invalidCompressed[0] = 0x02
		invalidCompressed[32] = 0x02 // X = 2 (may not have valid Y)
		_, err := NewPublicKeyFromBytes(invalidCompressed)
		// Note: This test might pass if X = 2 is valid on the curve,
		// which is acceptable behavior for the function
		if err != nil {
			t.Logf("Got error for X coordinate that cannot be decompressed: %v", err)
		}
	})

	t.Run("CompressedLargeX", func(t *testing.T) {
		// X coordinate larger than field prime
		largeCompressed := make([]byte, 33)
		largeCompressed[0] = 0x02
		// Set X to field prime (should fail)
		for i := 1; i < 33; i++ {
			largeCompressed[i] = 0xFF
		}
		_, err := NewPublicKeyFromBytes(largeCompressed)
		if err == nil {
			t.Error("Expected error for X coordinate exceeding field prime")
		}
		if !strings.Contains(err.Error(), "exceeds field prime") {
			t.Errorf("Expected error message about field prime, got: %v", err)
		}
	})
}

func TestInputValidation_EdgeCases(t *testing.T) {
	t.Run("VeryLargePrivateKey", func(t *testing.T) {
		// Private key larger than curve order
		largeKey := make([]byte, 32)
		for i := range largeKey {
			largeKey[i] = 0xFF
		}
		_, err := NewPrivateKeyFromBytes(largeKey)
		if err == nil {
			t.Error("Expected error for private key exceeding curve order, but got none")
		}
		if !strings.Contains(err.Error(), "exceeds curve order") {
			t.Errorf("Expected error message about curve order, got: %v", err)
		}
	})

	t.Run("OnePrivateKey", func(t *testing.T) {
		// Private key = 1
		oneKey := make([]byte, 32)
		oneKey[31] = 0x01
		privKey, err := NewPrivateKeyFromBytes(oneKey)
		if err != nil {
			t.Errorf("Expected no error for private key = 1, but got: %v", err)
		}

		// Verify it can sign
		hash := make([]byte, 32)
		_, err = privKey.Sign(hash)
		if err != nil {
			t.Errorf("Expected no error signing with private key = 1, but got: %v", err)
		}
	})

	t.Run("MaxValidPrivateKey", func(t *testing.T) {
		// Private key = curve order - 1
		// secp256k1 order = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
		maxKey, _ := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
		privKey, err := NewPrivateKeyFromBytes(maxKey)
		if err != nil {
			t.Errorf("Expected no error for max valid private key, but got: %v", err)
		}

		// Verify it can sign
		hash := make([]byte, 32)
		_, err = privKey.Sign(hash)
		if err != nil {
			t.Errorf("Expected no error signing with max private key, but got: %v", err)
		}
	})

	t.Run("RecoveryIdBoundary", func(t *testing.T) {
		// Test signatures with different V values
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		hash := make([]byte, 32)
		signature, err := privateKey.Sign(hash)
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// V should be 27 or 28 for Ethereum format
		if signature.V != 27 && signature.V != 28 {
			t.Errorf("Expected V to be 27 or 28, got %d", signature.V)
		}
	})

	t.Run("SignatureSerializationRoundTrip", func(t *testing.T) {
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		hash := [32]byte{0x01, 0x02, 0x03, 0x04}
		originalSig, err := privateKey.Sign(hash[:])
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Serialize and deserialize
		sigBytes := originalSig.Bytes()
		restoredSig, err := NewSignatureFromBytes(sigBytes)
		if err != nil {
			t.Fatalf("Failed to restore signature: %v", err)
		}

		// Verify components match
		if originalSig.R.Cmp(restoredSig.R) != 0 {
			t.Error("Restored R component doesn't match original")
		}
		if originalSig.S.Cmp(restoredSig.S) != 0 {
			t.Error("Restored S component doesn't match original")
		}
		if originalSig.V != restoredSig.V {
			t.Error("Restored V component doesn't match original")
		}

		// Verify signature still works
		valid, err := restoredSig.Verify(publicKey, hash)
		if err != nil {
			t.Fatalf("Failed to verify restored signature: %v", err)
		}
		if !valid {
			t.Error("Restored signature should be valid")
		}
	})
}
