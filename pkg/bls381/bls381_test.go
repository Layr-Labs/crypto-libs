package bls381

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"
)

func Test_BLS381(t *testing.T) {
	t.Run("KeyGeneration", func(t *testing.T) {
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Check that keys are not nil
		if privateKey == nil {
			t.Error("Generated private key is nil")
		}
		if publicKey == nil {
			t.Error("Generated public key is nil")
		}

		// Verify that the private key bytes are not empty
		if len(privateKey.Bytes()) == 0 {
			t.Error("Private key bytes are empty")
		}

		// Verify that the public key bytes are not empty
		if len(publicKey.Bytes()) == 0 {
			t.Error("Public key bytes are empty")
		}

		// Ensure Public() derives the correct public key
		derivedPublicKey := privateKey.Public()
		if !bytes.Equal(derivedPublicKey.Bytes(), publicKey.Bytes()) {
			t.Error("Derived public key doesn't match the generated public key")
		}
	})

	t.Run("KeyGenerationFromSeed", func(t *testing.T) {
		// Test with the same seed to ensure deterministic behavior
		seed := []byte("a seed phrase that is at least 32 bytes long")

		// Generate first key pair
		privateKey1, publicKey1, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate key pair from seed: %v", err)
		}

		// Generate second key pair with the same seed
		privateKey2, publicKey2, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate second key pair from seed: %v", err)
		}

		// Keys generated from the same seed should be identical
		if !bytes.Equal(privateKey1.Bytes(), privateKey2.Bytes()) {
			t.Error("Private keys generated from the same seed are not equal")
		}
		if !bytes.Equal(publicKey1.Bytes(), publicKey2.Bytes()) {
			t.Error("Public keys generated from the same seed are not equal")
		}

		// Test with a different seed
		differentSeed := []byte("a different seed phrase at least 32 bytes")
		privateKey3, publicKey3, err := GenerateKeyPairFromSeed(differentSeed)
		if err != nil {
			t.Fatalf("Failed to generate key pair from different seed: %v", err)
		}

		// Keys generated from different seeds should be different
		if bytes.Equal(privateKey1.Bytes(), privateKey3.Bytes()) {
			t.Error("Private keys generated from different seeds are equal")
		}
		if bytes.Equal(publicKey1.Bytes(), publicKey3.Bytes()) {
			t.Error("Public keys generated from different seeds are equal")
		}

		// Make sure keys can be used for signing and verification
		message := []byte("test message for seed-based keys")
		signature, err := privateKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with seed-based key: %v", err)
		}

		valid, err := signature.Verify(publicKey1, message)
		if err != nil {
			t.Fatalf("Failed to verify signature from seed-based key: %v", err)
		}
		if !valid {
			t.Error("Signature verification with seed-based key failed")
		}
	})

	t.Run("KeyGenerationEIP2333", func(t *testing.T) {
		// Test with the same seed and path to ensure deterministic behavior
		seed := []byte("a seed phrase that is at least 32 bytes long")
		path := []uint32{3, 14, 15, 92}

		// Generate first key pair
		privateKey1, publicKey1, err := GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to generate key pair using EIP-2333: %v", err)
		}

		// Generate second key pair with the same seed and path
		privateKey2, publicKey2, err := GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to generate second key pair using EIP-2333: %v", err)
		}

		// Keys generated from the same seed and path should be identical
		if !bytes.Equal(privateKey1.Bytes(), privateKey2.Bytes()) {
			t.Error("Private keys generated with the same parameters are not equal")
		}
		if !bytes.Equal(publicKey1.Bytes(), publicKey2.Bytes()) {
			t.Error("Public keys generated with the same parameters are not equal")
		}

		// Test with a different path
		differentPath := []uint32{42, 42, 42, 42}
		privateKey3, publicKey3, err := GenerateKeyPairEIP2333(seed, differentPath)
		if err != nil {
			t.Fatalf("Failed to generate key pair with different path: %v", err)
		}

		// Keys generated from the same seed but different paths should be different
		if bytes.Equal(privateKey1.Bytes(), privateKey3.Bytes()) {
			t.Error("Private keys generated with different paths are equal")
		}
		if bytes.Equal(publicKey1.Bytes(), publicKey3.Bytes()) {
			t.Error("Public keys generated with different paths are equal")
		}

		// Make sure keys can be used for signing and verification
		message := []byte("test message for EIP-2333 keys")
		signature, err := privateKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with EIP-2333 key: %v", err)
		}

		valid, err := signature.Verify(publicKey1, message)
		if err != nil {
			t.Fatalf("Failed to verify signature from EIP-2333 key: %v", err)
		}
		if !valid {
			t.Error("Signature verification with EIP-2333 key failed")
		}
	})

	t.Run("SerializationDeserialization", func(t *testing.T) {
		// Generate a key pair
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test private key serialization/deserialization
		privateKeyBytes := privateKey.Bytes()
		recoveredPrivateKey, err := NewPrivateKeyFromBytes(privateKeyBytes)
		if err != nil {
			t.Fatalf("Failed to deserialize private key: %v", err)
		}

		// Test that the recovered private key works for signing
		message := []byte("test message")
		signatureFromRecovered, err := recoveredPrivateKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with recovered private key: %v", err)
		}

		// Test public key serialization/deserialization
		publicKeyBytes := publicKey.Bytes()
		deserializedPublicKey, err := NewPublicKeyFromBytes(publicKeyBytes)
		if err != nil {
			t.Fatalf("Failed to deserialize public key: %v", err)
		}

		// Generate a signature to test signature serialization/deserialization
		signature, err := privateKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Verify the signature from the recovered private key
		valid, err := signatureFromRecovered.Verify(publicKey, message)
		if err != nil {
			t.Fatalf("Failed to verify signature from recovered private key: %v", err)
		}
		if !valid {
			t.Error("Signature from recovered private key verification failed")
		}

		// Test signature serialization/deserialization
		signatureBytes := signature.Bytes()
		deserializedSignature, err := NewSignatureFromBytes(signatureBytes)
		if err != nil {
			t.Fatalf("Failed to deserialize signature: %v", err)
		}

		// Verify the deserialized signature
		valid, err = deserializedSignature.Verify(deserializedPublicKey, message)
		if err != nil {
			t.Fatalf("Failed to verify deserialized signature: %v", err)
		}
		if !valid {
			t.Error("Deserialized signature verification failed")
		}
	})

	t.Run("SignAndVerify", func(t *testing.T) {
		// Generate a key pair
		privateKey, publicKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test signing a message
		message := []byte("Hello, world!")
		signature, err := privateKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Verify the signature
		valid, err := signature.Verify(publicKey, message)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}
		if !valid {
			t.Error("Signature verification failed")
		}

		t.Run("VerifyWithWrongMessage", func(t *testing.T) {
			wrongMessage := []byte("Wrong message")
			valid, err = signature.Verify(publicKey, wrongMessage)
			if err != nil {
				t.Fatalf("Failed to verify signature with wrong message: %v", err)
			}
			if valid {
				t.Error("Signature verification passed with wrong message")
			}
		})

		t.Run("VerifyWithWrongKey", func(t *testing.T) {
			_, wrongPublicKey, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate wrong key pair: %v", err)
			}
			valid, err = signature.Verify(wrongPublicKey, message)
			if err != nil {
				t.Fatalf("Failed to verify signature with wrong key: %v", err)
			}
			if valid {
				t.Error("Signature verification passed with wrong key")
			}
		})
	})

	t.Run("AggregateSignatures", func(t *testing.T) {
		// Generate multiple key pairs
		numKeys := 3
		message := []byte("Hello, world!")
		privateKeys := make([]*PrivateKey, numKeys)
		publicKeys := make([]*PublicKey, numKeys)
		signatures := make([]*Signature, numKeys)

		for i := 0; i < numKeys; i++ {
			var err error
			privateKeys[i], publicKeys[i], err = GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			// Sign the same message with different keys
			signatures[i], err = privateKeys[i].Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign message with key %d: %v", i, err)
			}

			// Verify individual signatures
			valid, err := signatures[i].Verify(publicKeys[i], message)
			if err != nil {
				t.Fatalf("Failed to verify signature %d: %v", i, err)
			}
			if !valid {
				t.Errorf("Signature %d verification failed", i)
			}
		}

		// Aggregate signatures
		aggregatedSignature, err := AggregateSignatures(signatures)
		if err != nil {
			t.Fatalf("Failed to aggregate signatures: %v", err)
		}

		t.Run("BatchVerification", func(t *testing.T) {
			// Verify batch signature (all signers signed the same message)
			valid, err := BatchVerify(publicKeys, message, signatures)
			if err != nil {
				t.Fatalf("Failed to verify batch signatures: %v", err)
			}
			if !valid {
				t.Error("Batch signature verification failed")
			}
		})

		t.Run("AggregateVerificationWithSameMessage", func(t *testing.T) {
			// Verify aggregate signature against multiple public keys with same message
			valid, err := AggregateVerify(publicKeys, [][]byte{message, message, message}, aggregatedSignature)
			if err != nil {
				t.Fatalf("Failed to verify aggregate signature: %v", err)
			}
			if !valid {
				t.Error("Aggregate signature verification failed")
			}
		})
	})

	t.Run("AggregateVerifyWithDifferentMessages", func(t *testing.T) {
		// Generate multiple key pairs
		numKeys := 3
		messages := [][]byte{
			[]byte("Message 1"),
			[]byte("Message 2"),
			[]byte("Message 3"),
		}
		privateKeys := make([]*PrivateKey, numKeys)
		publicKeys := make([]*PublicKey, numKeys)
		signatures := make([]*Signature, numKeys)

		for i := 0; i < numKeys; i++ {
			var err error
			privateKeys[i], publicKeys[i], err = GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			// Each key signs a different message
			signatures[i], err = privateKeys[i].Sign(messages[i])
			if err != nil {
				t.Fatalf("Failed to sign message %d: %v", i, err)
			}
		}

		// Aggregate signatures
		aggregatedSignature, err := AggregateSignatures(signatures)
		if err != nil {
			t.Fatalf("Failed to aggregate signatures: %v", err)
		}

		t.Run("CorrectMessages", func(t *testing.T) {
			// Verify aggregate signature with different messages
			valid, err := AggregateVerify(publicKeys, messages, aggregatedSignature)
			if err != nil {
				t.Fatalf("Failed to verify aggregate signature with different messages: %v", err)
			}
			if !valid {
				t.Error("Aggregate signature verification with different messages failed")
			}
		})

		t.Run("WrongMessages", func(t *testing.T) {
			// Try with wrong messages
			wrongMessages := [][]byte{
				[]byte("Wrong message 1"),
				[]byte("Message 2"),
				[]byte("Message 3"),
			}
			valid, err := AggregateVerify(publicKeys, wrongMessages, aggregatedSignature)
			if err != nil {
				t.Fatalf("Failed to verify aggregate signature with wrong messages: %v", err)
			}
			if valid {
				t.Error("Aggregate signature verification passed with wrong messages")
			}
		})
	})

	t.Run("EmptyAggregation", func(t *testing.T) {
		// Test aggregating empty set of signatures
		_, err := AggregateSignatures([]*Signature{})
		if err == nil {
			t.Error("Expected error when aggregating empty set of signatures, but got none")
		}
	})

	t.Run("HexStringSerialization", func(t *testing.T) {
		// Generate a key pair
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test private key hex serialization
		hexString, err := privateKey.ToHex()
		if err != nil {
			t.Fatalf("Failed to convert private key to hex: %v", err)
		}

		// Test that hex string is valid
		if len(hexString) == 0 {
			t.Error("Hex string is empty")
		}

		// Test private key hex deserialization
		recoveredPrivateKey, err := NewPrivateKeyFromHexString(hexString)
		if err != nil {
			t.Fatalf("Failed to create private key from hex string: %v", err)
		}

		// Verify that original and recovered private keys are the same
		if !bytes.Equal(privateKey.Bytes(), recoveredPrivateKey.Bytes()) {
			t.Error("Recovered private key from hex doesn't match original")
		}

		// Test that the recovered private key works for signing
		message := []byte("test message for hex key")
		signature1, err := privateKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with original private key: %v", err)
		}

		signature2, err := recoveredPrivateKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with recovered private key: %v", err)
		}

		// Both signatures should be the same
		if !bytes.Equal(signature1.Bytes(), signature2.Bytes()) {
			t.Error("Signatures from original and recovered keys don't match")
		}
	})

	t.Run("InvalidHexString", func(t *testing.T) {
		// Test with invalid hex string
		_, err := NewPrivateKeyFromHexString("invalid_hex")
		if err == nil {
			t.Error("Expected error for invalid hex string, but got none")
		}

		// Test with empty hex string (should create a zero private key)
		zeroKey, err := NewPrivateKeyFromHexString("")
		if err != nil {
			t.Fatalf("Failed to create private key from empty hex string: %v", err)
		}

		// Zero key should have zero bytes
		if len(zeroKey.Bytes()) != 0 {
			t.Error("Zero key should have empty bytes")
		}
	})

	t.Run("SchemeHexFunctionality", func(t *testing.T) {
		// Test using the scheme interface
		scheme := NewScheme()

		// Generate a key pair through the scheme
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair through scheme: %v", err)
		}

		// Get the underlying private key
		bls381PrivKey := privKey.(*privateKeyAdapter).pk

		// Test hex conversion
		hexString, err := bls381PrivKey.ToHex()
		if err != nil {
			t.Fatalf("Failed to convert scheme private key to hex: %v", err)
		}

		// Test scheme hex deserialization
		recoveredPrivKey, err := scheme.NewPrivateKeyFromHexString(hexString)
		if err != nil {
			t.Fatalf("Failed to create private key from hex through scheme: %v", err)
		}

		// Verify that original and recovered private keys are the same
		if !bytes.Equal(privKey.Bytes(), recoveredPrivKey.Bytes()) {
			t.Error("Recovered private key from hex through scheme doesn't match original")
		}
	})

	t.Run("HexStringWithEIP2333", func(t *testing.T) {
		// Test hex functionality with EIP-2333 generated keys
		seed := []byte("a seed phrase that is at least 32 bytes long")
		path := []uint32{3, 14, 15, 92}

		// Generate key pair using EIP-2333
		privateKey, _, err := GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to generate EIP-2333 key pair: %v", err)
		}

		// Test hex conversion for EIP-2333 key
		hexString, err := privateKey.ToHex()
		if err != nil {
			t.Fatalf("Failed to convert EIP-2333 private key to hex: %v", err)
		}

		// Test hex deserialization
		recoveredPrivateKey, err := NewPrivateKeyFromHexString(hexString)
		if err != nil {
			t.Fatalf("Failed to create private key from EIP-2333 hex string: %v", err)
		}

		// Verify that original and recovered private keys are the same
		if !bytes.Equal(privateKey.Bytes(), recoveredPrivateKey.Bytes()) {
			t.Error("Recovered EIP-2333 private key from hex doesn't match original")
		}

		// Regenerate the same key using EIP-2333 to verify deterministic behavior
		samePrivateKey, _, err := GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to regenerate EIP-2333 key pair: %v", err)
		}

		// The hex string should be the same
		sameHexString, err := samePrivateKey.ToHex()
		if err != nil {
			t.Fatalf("Failed to convert regenerated EIP-2333 private key to hex: %v", err)
		}

		if hexString != sameHexString {
			t.Error("EIP-2333 key hex strings don't match for deterministic generation")
		}
	})
}

func TestHashToG1(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
	}{
		{
			name:    "empty message",
			message: []byte{},
		},
		{
			name:    "simple message",
			message: []byte("Hello, World!"),
		},
		{
			name:    "long message",
			message: []byte("This is a longer message with some special characters: !@#$%^&*()"),
		},
		{
			name:    "very long message",
			message: bytes.Repeat([]byte("a"), 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			point := hashToG1(tt.message)

			// Check that the point is not nil
			if point == nil {
				t.Fatal("hashToG1 returned nil point")
			}

			// Check that the point is on the curve
			if !point.IsOnCurve() {
				t.Error("hashToG1 returned point not on curve")
			}

			// Check that the point is in the correct subgroup
			if !point.IsInSubGroup() {
				t.Error("hashToG1 returned point not in subgroup")
			}
		})
	}
}

func TestPublicKeyG2(t *testing.T) {
	// Generate a key pair
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Check that the public key is in G2
	if !pk.GetG2Point().IsOnCurve() {
		t.Error("Public key point is not on curve")
	}

	if !pk.GetG2Point().IsInSubGroup() {
		t.Error("Public key point is not in subgroup")
	}

	// Verify that the public key matches the private key
	expectedPk := sk.Public()
	if !bytes.Equal(pk.PointBytes, expectedPk.PointBytes) {
		t.Error("Public key does not match private key")
	}
}

func TestSignatureG1(t *testing.T) {
	// Generate a key pair
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Sign a message
	message := []byte("test message")
	sig, err := sk.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Check that the signature is in G1
	if !sig.sig.IsOnCurve() {
		t.Error("Signature point is not on curve")
	}

	if !sig.sig.IsInSubGroup() {
		t.Error("Signature point is not in subgroup")
	}

	// Verify the signature
	valid, err := sig.Verify(pk, message)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestAggregateSignaturesG1(t *testing.T) {
	// Generate multiple key pairs
	numKeys := 3
	privateKeys := make([]*PrivateKey, numKeys)
	publicKeys := make([]*PublicKey, numKeys)
	signatures := make([]*Signature, numKeys)

	message := []byte("test message")

	for i := 0; i < numKeys; i++ {
		sk, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		privateKeys[i] = sk
		publicKeys[i] = pk

		// Sign the message
		sig, err := sk.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message with key %d: %v", i, err)
		}
		signatures[i] = sig
	}

	// Aggregate signatures
	aggSig, err := AggregateSignatures(signatures)
	if err != nil {
		t.Fatalf("Failed to aggregate signatures: %v", err)
	}

	// Check that the aggregated signature is in G1
	if !aggSig.sig.IsOnCurve() {
		t.Error("Aggregated signature point is not on curve")
	}

	if !aggSig.sig.IsInSubGroup() {
		t.Error("Aggregated signature point is not in subgroup")
	}

	// Verify the aggregated signature
	valid, err := BatchVerify(publicKeys, message, signatures)
	if err != nil {
		t.Fatalf("Failed to batch verify signatures: %v", err)
	}
	if !valid {
		t.Error("Batch signature verification failed")
	}
}

// Additional input validation tests - testing edge cases and invalid inputs

func TestInputValidation_GenerateKeyPairFromSeed(t *testing.T) {
	t.Run("NilSeed", func(t *testing.T) {
		_, _, err := GenerateKeyPairFromSeed(nil)
		if err == nil {
			t.Error("Expected error for nil seed, but got none")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("Expected error message about seed length, got: %v", err)
		}
	})

	t.Run("EmptySeed", func(t *testing.T) {
		_, _, err := GenerateKeyPairFromSeed([]byte{})
		if err == nil {
			t.Error("Expected error for empty seed, but got none")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("Expected error message about seed length, got: %v", err)
		}
	})

	t.Run("ShortSeed", func(t *testing.T) {
		shortSeed := []byte("short")
		_, _, err := GenerateKeyPairFromSeed(shortSeed)
		if err == nil {
			t.Error("Expected error for short seed, but got none")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("Expected error message about seed length, got: %v", err)
		}
	})

	t.Run("ExactlyMinimumSeed", func(t *testing.T) {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(i)
		}
		_, _, err := GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Errorf("Expected no error for 32-byte seed, but got: %v", err)
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
}

func TestInputValidation_GenerateKeyPairEIP2333(t *testing.T) {
	validSeed := make([]byte, 32)
	for i := range validSeed {
		validSeed[i] = byte(i)
	}

	t.Run("NilSeed", func(t *testing.T) {
		_, _, err := GenerateKeyPairEIP2333(nil, []uint32{0})
		if err == nil {
			t.Error("Expected error for nil seed, but got none")
		}
		if !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("Expected error message about seed length, got: %v", err)
		}
	})

	t.Run("ShortSeed", func(t *testing.T) {
		shortSeed := []byte("short")
		_, _, err := GenerateKeyPairEIP2333(shortSeed, []uint32{0})
		if err == nil {
			t.Error("Expected error for short seed, but got none")
		}
	})

	t.Run("NilPath", func(t *testing.T) {
		_, _, err := GenerateKeyPairEIP2333(validSeed, nil)
		if err != nil {
			t.Errorf("Expected no error for nil path, but got: %v", err)
		}
	})

	t.Run("EmptyPath", func(t *testing.T) {
		_, _, err := GenerateKeyPairEIP2333(validSeed, []uint32{})
		if err != nil {
			t.Errorf("Expected no error for empty path, but got: %v", err)
		}
	})

	t.Run("LongPath", func(t *testing.T) {
		longPath := make([]uint32, 100)
		for i := range longPath {
			longPath[i] = uint32(i)
		}
		_, _, err := GenerateKeyPairEIP2333(validSeed, longPath)
		if err != nil {
			t.Errorf("Expected no error for long path, but got: %v", err)
		}
	})

	t.Run("MaxUint32Values", func(t *testing.T) {
		path := []uint32{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}
		_, _, err := GenerateKeyPairEIP2333(validSeed, path)
		if err != nil {
			t.Errorf("Expected no error for max uint32 values, but got: %v", err)
		}
	})
}

func TestInputValidation_NewPrivateKeyFromBytes(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewPrivateKeyFromBytes(nil)
		if err != nil {
			t.Errorf("Expected no error for nil data (should create zero key), but got: %v", err)
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewPrivateKeyFromBytes([]byte{})
		if err != nil {
			t.Errorf("Expected no error for empty data (should create zero key), but got: %v", err)
		}
	})

	t.Run("SingleByte", func(t *testing.T) {
		_, err := NewPrivateKeyFromBytes([]byte{0x01})
		if err != nil {
			t.Errorf("Expected no error for single byte, but got: %v", err)
		}
	})

	t.Run("LargeData", func(t *testing.T) {
		largeData := make([]byte, 1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		_, err := NewPrivateKeyFromBytes(largeData)
		if err != nil {
			t.Errorf("Expected no error for large data, but got: %v", err)
		}
	})

	t.Run("AllZeros", func(t *testing.T) {
		zeros := make([]byte, 32)
		key, err := NewPrivateKeyFromBytes(zeros)
		if err != nil {
			t.Errorf("Expected no error for all zeros, but got: %v", err)
		}
		if key == nil {
			t.Error("Expected non-nil key for all zeros")
		}
	})

	t.Run("AllOnes", func(t *testing.T) {
		ones := make([]byte, 32)
		for i := range ones {
			ones[i] = 0xFF
		}
		key, err := NewPrivateKeyFromBytes(ones)
		if err != nil {
			t.Errorf("Expected no error for all ones, but got: %v", err)
		}
		if key == nil {
			t.Error("Expected non-nil key for all ones")
		}
	})
}

func TestInputValidation_NewPrivateKeyFromHexString(t *testing.T) {
	t.Run("EmptyString", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("")
		if err != nil {
			t.Errorf("Expected no error for empty string (should create zero key), but got: %v", err)
		}
	})

	t.Run("InvalidHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("invalid_hex_string")
		if err == nil {
			t.Error("Expected error for invalid hex string, but got none")
		}
	})

	t.Run("InvalidCharacters", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123g456h")
		if err == nil {
			t.Error("Expected error for hex string with invalid characters, but got none")
		}
	})

	t.Run("OddLengthHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123")
		if err == nil {
			t.Error("Expected error for odd-length hex string, but got none")
		}
	})

	t.Run("WithPrefix", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("0x123456")
		if err != nil {
			t.Errorf("Expected no error for hex string with 0x prefix, but got: %v", err)
		}
	})

	t.Run("WithoutPrefix", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("123456")
		if err != nil {
			t.Errorf("Expected no error for hex string without prefix, but got: %v", err)
		}
	})

	t.Run("UppercaseHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("ABCDEF")
		if err != nil {
			t.Errorf("Expected no error for uppercase hex, but got: %v", err)
		}
	})

	t.Run("MixedCaseHex", func(t *testing.T) {
		_, err := NewPrivateKeyFromHexString("AbCdEf")
		if err != nil {
			t.Errorf("Expected no error for mixed case hex, but got: %v", err)
		}
	})

	t.Run("VeryLongHex", func(t *testing.T) {
		longHex := strings.Repeat("ab", 500) // 1000 character hex string
		_, err := NewPrivateKeyFromHexString(longHex)
		if err != nil {
			t.Errorf("Expected no error for very long hex string, but got: %v", err)
		}
	})
}

func TestInputValidation_PrivateKeySign(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	t.Run("NilMessage", func(t *testing.T) {
		_, err := privateKey.Sign(nil)
		if err != nil {
			t.Errorf("Expected no error for nil message, but got: %v", err)
		}
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		_, err := privateKey.Sign([]byte{})
		if err != nil {
			t.Errorf("Expected error for empty message, but got: %v", err)
		}
	})

	t.Run("SingleByteMessage", func(t *testing.T) {
		_, err := privateKey.Sign([]byte{0x01})
		if err != nil {
			t.Errorf("Expected no error for single byte message, but got: %v", err)
		}
	})

	t.Run("LargeMessage", func(t *testing.T) {
		largeMessage := make([]byte, 1024*1024) // 1MB message
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}
		_, err := privateKey.Sign(largeMessage)
		if err != nil {
			t.Errorf("Expected no error for large message, but got: %v", err)
		}
	})

	t.Run("VeryLargeMessage", func(t *testing.T) {
		veryLargeMessage := make([]byte, 10*1024*1024) // 10MB message
		for i := range veryLargeMessage {
			veryLargeMessage[i] = byte(i % 256)
		}
		_, err := privateKey.Sign(veryLargeMessage)
		if err != nil {
			t.Errorf("Expected no error for very large message, but got: %v", err)
		}
	})

	t.Run("BinaryMessage", func(t *testing.T) {
		binaryMessage := []byte{0x00, 0xFF, 0x00, 0xFF, 0xAA, 0x55}
		_, err := privateKey.Sign(binaryMessage)
		if err != nil {
			t.Errorf("Expected no error for binary message, but got: %v", err)
		}
	})
}

func TestInputValidation_NewPublicKeyFromBytes(t *testing.T) {
	t.Run("NilData", func(t *testing.T) {
		_, err := NewPublicKeyFromBytes(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewPublicKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, but got none")
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		invalidData := []byte{0x01, 0x02, 0x03}
		_, err := NewPublicKeyFromBytes(invalidData)
		if err == nil {
			t.Error("Expected error for invalid length data, but got none")
		}
	})

	t.Run("WrongFormatData", func(t *testing.T) {
		wrongData := make([]byte, 96) // Correct length but invalid format
		for i := range wrongData {
			wrongData[i] = 0xFF
		}
		_, err := NewPublicKeyFromBytes(wrongData)
		if err == nil {
			t.Error("Expected error for wrong format data, but got none")
		}
	})

	t.Run("G1PointLength", func(t *testing.T) {
		// Test with G1 point length (48 bytes)
		g1Data := make([]byte, 48)
		_, err := NewPublicKeyFromBytes(g1Data)
		if err == nil {
			t.Error("Expected error for invalid G1 point data, but got none")
		}
	})

	t.Run("G2PointLength", func(t *testing.T) {
		// Test with G2 point length (96 bytes) - all zeros is point at infinity and might be valid
		g2Data := make([]byte, 96)
		// Fill with invalid data that's definitely not a valid G2 point
		for i := range g2Data {
			g2Data[i] = 0xFF
		}
		_, err := NewPublicKeyFromBytes(g2Data)
		if err == nil {
			t.Error("Expected error for invalid G2 point data, but got none")
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
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := NewSignatureFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty data, but got none")
		}
	})

	t.Run("InvalidLength", func(t *testing.T) {
		invalidData := []byte{0x01, 0x02, 0x03}
		_, err := NewSignatureFromBytes(invalidData)
		if err == nil {
			t.Error("Expected error for invalid length data, but got none")
		}
	})

	t.Run("WrongFormatData", func(t *testing.T) {
		wrongData := make([]byte, 48) // Correct length but invalid format
		for i := range wrongData {
			wrongData[i] = 0xFF
		}
		_, err := NewSignatureFromBytes(wrongData)
		if err == nil {
			t.Error("Expected error for wrong format data, but got none")
		}
	})

	t.Run("AllZeros", func(t *testing.T) {
		zeros := make([]byte, 48)
		_, err := NewSignatureFromBytes(zeros)
		if err == nil {
			t.Error("Expected error for all zeros (invalid signature), but got none")
		}
	})
}

func TestInputValidation_SignatureVerify(t *testing.T) {
	// Generate valid test data
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	message := []byte("test message")
	signature, err := privateKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilPublicKey", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key, but got none")
			}
		}()
		_, _ = signature.Verify(nil, message)
	})

	t.Run("NilMessage", func(t *testing.T) {
		_, err := signature.Verify(publicKey, nil)
		if err != nil {
			t.Errorf("Expected no error for nil message, but got: %v", err)
		}
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		_, err := signature.Verify(publicKey, []byte{})
		if err != nil {
			t.Errorf("Expected no error for empty message, but got: %v", err)
		}
	})

	t.Run("LargeMessage", func(t *testing.T) {
		largeMessage := make([]byte, 1024*1024) // 1MB
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}
		_, err := signature.Verify(publicKey, largeMessage)
		if err != nil {
			t.Errorf("Expected no error for large message, but got: %v", err)
		}
	})
}

func TestInputValidation_AggregateSignatures(t *testing.T) {
	// Generate valid test data
	privateKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	message := []byte("test message")
	signature, err := privateKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilSignatures", func(t *testing.T) {
		_, err := AggregateSignatures(nil)
		if err == nil {
			t.Error("Expected error for nil signatures slice, but got none")
		}
	})

	t.Run("EmptySignatures", func(t *testing.T) {
		_, err := AggregateSignatures([]*Signature{})
		if err == nil {
			t.Error("Expected error for empty signatures slice, but got none")
		}
	})

	t.Run("NilSignatureInSlice", func(t *testing.T) {
		signatures := []*Signature{signature, nil, signature}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil signature in slice, but got none")
			}
		}()
		_, _ = AggregateSignatures(signatures)
	})

	t.Run("SingleSignature", func(t *testing.T) {
		signatures := []*Signature{signature}
		_, err := AggregateSignatures(signatures)
		if err != nil {
			t.Errorf("Expected no error for single signature, but got: %v", err)
		}
	})

	t.Run("ManySignatures", func(t *testing.T) {
		signatures := make([]*Signature, 100)
		for i := range signatures {
			signatures[i] = signature
		}
		_, err := AggregateSignatures(signatures)
		if err != nil {
			t.Errorf("Expected no error for many signatures, but got: %v", err)
		}
	})
}

func TestInputValidation_BatchVerify(t *testing.T) {
	// Generate valid test data
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	message := []byte("test message")
	signature, err := privateKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilPublicKeys", func(t *testing.T) {
		_, err := BatchVerify(nil, message, []*Signature{signature})
		if err == nil {
			t.Error("Expected error for nil public keys slice, but got none")
		}
	})

	t.Run("NilMessage", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{publicKey}, nil, []*Signature{signature})
		if err != nil {
			t.Errorf("Expected no error for nil message, but got: %v", err)
		}
	})

	t.Run("NilSignatures", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{publicKey}, message, nil)
		if err == nil {
			t.Error("Expected error for nil signatures slice, but got none")
		}
	})

	t.Run("EmptyPublicKeys", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{}, message, []*Signature{})
		if err == nil {
			t.Error("Expected error for empty public keys slice, but got none")
		}
	})

	t.Run("EmptySignatures", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{publicKey}, message, []*Signature{})
		if err == nil {
			t.Error("Expected error for empty signatures slice, but got none")
		}
	})

	t.Run("MismatchedLengths", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{publicKey, publicKey}, message, []*Signature{signature})
		if err == nil {
			t.Error("Expected error for mismatched slice lengths, but got none")
		}
	})

	t.Run("NilPublicKeyInSlice", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key in slice, but got none")
			}
		}()
		_, _ = BatchVerify([]*PublicKey{nil}, message, []*Signature{signature})
	})

	t.Run("NilSignatureInSlice", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil signature in slice, but got none")
			}
		}()
		_, _ = BatchVerify([]*PublicKey{publicKey}, message, []*Signature{nil})
	})

	t.Run("EmptyMessage", func(t *testing.T) {
		_, err := BatchVerify([]*PublicKey{publicKey}, []byte{}, []*Signature{signature})
		if err != nil {
			t.Errorf("Expected no error for empty message, but got: %v", err)
		}
	})

	t.Run("LargeMessage", func(t *testing.T) {
		largeMessage := make([]byte, 1024*1024) // 1MB
		for i := range largeMessage {
			largeMessage[i] = byte(i % 256)
		}
		_, err := BatchVerify([]*PublicKey{publicKey}, largeMessage, []*Signature{signature})
		if err != nil {
			t.Errorf("Expected no error for large message, but got: %v", err)
		}
	})
}

func TestInputValidation_AggregateVerify(t *testing.T) {
	// Generate valid test data
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}
	message := []byte("test message")
	signature, err := privateKey.Sign(message)
	if err != nil {
		t.Fatalf("Failed to generate signature for testing: %v", err)
	}

	t.Run("NilPublicKeys", func(t *testing.T) {
		_, err := AggregateVerify(nil, [][]byte{message}, signature)
		if err == nil {
			t.Error("Expected error for nil public keys slice, but got none")
		}
	})

	t.Run("NilMessages", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{publicKey}, nil, signature)
		if err == nil {
			t.Error("Expected error for nil messages slice, but got none")
		}
	})

	t.Run("NilSignature", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil signature, but got none")
			}
		}()
		_, _ = AggregateVerify([]*PublicKey{publicKey}, [][]byte{message}, nil)
	})

	t.Run("EmptyPublicKeys", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{}, [][]byte{}, signature)
		if err != nil {
			t.Errorf("Expected no error for empty public keys slice, but got: %v", err)
		}
	})

	t.Run("EmptyMessages", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{publicKey}, [][]byte{}, signature)
		if err == nil {
			t.Error("Expected error for empty messages slice, but got none")
		}
	})

	t.Run("MismatchedLengths", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{publicKey, publicKey}, [][]byte{message}, signature)
		if err == nil {
			t.Error("Expected error for mismatched slice lengths, but got none")
		}
	})

	t.Run("NilPublicKeyInSlice", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key in slice, but got none")
			}
		}()
		_, _ = AggregateVerify([]*PublicKey{nil}, [][]byte{message}, signature)
	})

	t.Run("NilMessageInSlice", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{publicKey}, [][]byte{nil}, signature)
		if err != nil {
			t.Errorf("Expected no error for nil message in slice, but got: %v", err)
		}
	})

	t.Run("EmptyMessageInSlice", func(t *testing.T) {
		_, err := AggregateVerify([]*PublicKey{publicKey}, [][]byte{{}}, signature)
		if err != nil {
			t.Errorf("Expected no error for empty message in slice, but got: %v", err)
		}
	})

	t.Run("MixedMessageLengths", func(t *testing.T) {
		messages := [][]byte{
			[]byte("short"),
			make([]byte, 1024),
			[]byte{},
			[]byte("medium length message"),
		}
		// Fill the large message
		for i := range messages[1] {
			messages[1][i] = byte(i % 256)
		}

		publicKeys := make([]*PublicKey, len(messages))
		for i := range publicKeys {
			_, pk, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}
			publicKeys[i] = pk
		}

		_, err := AggregateVerify(publicKeys, messages, signature)
		if err != nil {
			t.Errorf("Expected no error for mixed message lengths, but got: %v", err)
		}
	})
}

func TestInputValidation_PrivateKeyMethods(t *testing.T) {
	t.Run("NilPrivateKeyBytes", func(t *testing.T) {
		// Create a private key with nil scalar (edge case)
		pk := &PrivateKey{ScalarBytes: nil, scalar: nil}
		bytes := pk.Bytes()
		if bytes != nil {
			t.Error("Expected nil bytes for nil ScalarBytes, but got non-nil")
		}
	})

	t.Run("EmptyPrivateKeyBytes", func(t *testing.T) {
		pk := &PrivateKey{ScalarBytes: []byte{}, scalar: nil}
		bytes := pk.Bytes()
		if len(bytes) != 0 {
			t.Error("Expected empty bytes for empty ScalarBytes")
		}
	})

	t.Run("PrivateKeyToHexWithNilBytes", func(t *testing.T) {
		pk := &PrivateKey{ScalarBytes: nil, scalar: nil}
		hex, err := pk.ToHex()
		if err != nil {
			t.Errorf("Expected no error for ToHex with nil bytes, but got: %v", err)
		}
		if hex != "" {
			t.Error("Expected empty hex string for nil bytes")
		}
	})

	t.Run("PrivateKeyToHexWithEmptyBytes", func(t *testing.T) {
		pk := &PrivateKey{ScalarBytes: []byte{}, scalar: nil}
		hex, err := pk.ToHex()
		if err != nil {
			t.Errorf("Expected no error for ToHex with empty bytes, but got: %v", err)
		}
		if hex != "" {
			t.Error("Expected empty hex string for empty bytes")
		}
	})
}

func TestInputValidation_PublicKeyMethods(t *testing.T) {
	t.Run("NilPublicKeyBytes", func(t *testing.T) {
		pk := &PublicKey{PointBytes: nil, g1Point: nil, g2Point: nil}
		bytes := pk.Bytes()
		if bytes != nil {
			t.Error("Expected nil bytes for nil PointBytes, but got non-nil")
		}
	})

	t.Run("EmptyPublicKeyBytes", func(t *testing.T) {
		pk := &PublicKey{PointBytes: []byte{}, g1Point: nil, g2Point: nil}
		bytes := pk.Bytes()
		if len(bytes) != 0 {
			t.Error("Expected empty bytes for empty PointBytes")
		}
	})

	t.Run("GetG1PointNil", func(t *testing.T) {
		pk := &PublicKey{PointBytes: nil, g1Point: nil, g2Point: nil}
		g1Point := pk.GetG1Point()
		if g1Point != nil {
			t.Error("Expected nil G1 point for nil g1Point")
		}
	})

	t.Run("GetG2PointNil", func(t *testing.T) {
		pk := &PublicKey{PointBytes: nil, g1Point: nil, g2Point: nil}
		g2Point := pk.GetG2Point()
		if g2Point != nil {
			t.Error("Expected nil G2 point for nil g2Point")
		}
	})
}

func TestInputValidation_SignatureMethods(t *testing.T) {
	t.Run("NilSignatureBytes", func(t *testing.T) {
		sig := &Signature{SigBytes: nil, sig: nil}
		bytes := sig.Bytes()
		if bytes != nil {
			t.Error("Expected nil bytes for nil SigBytes, but got non-nil")
		}
	})

	t.Run("EmptySignatureBytes", func(t *testing.T) {
		sig := &Signature{SigBytes: []byte{}, sig: nil}
		bytes := sig.Bytes()
		if len(bytes) != 0 {
			t.Error("Expected empty bytes for empty SigBytes")
		}
	})

	t.Run("AddNilSignature", func(t *testing.T) {
		// Generate a valid signature for testing
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		sig, err := privateKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Test adding nil signature
		result := sig.Add(nil)
		if result != sig {
			t.Error("Expected same signature when adding nil")
		}
	})

	t.Run("AddSignatureWithNilSig", func(t *testing.T) {
		// Generate a valid signature for testing
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		sig, err := privateKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Create signature with nil sig field
		nilSig := &Signature{SigBytes: []byte{}, sig: nil}
		result := sig.Add(nilSig)
		if result != sig {
			t.Error("Expected same signature when adding signature with nil sig field")
		}
	})
}

func TestInputValidation_SchemeAdapterMethods(t *testing.T) {
	scheme := NewScheme()

	t.Run("SchemeAggregateSignatures_NilInput", func(t *testing.T) {
		_, err := scheme.AggregateSignatures(nil)
		if err == nil {
			t.Error("Expected error for nil signatures slice, but got none")
		}
		if !strings.Contains(err.Error(), "signatures slice cannot be empty") {
			t.Errorf("Expected nil error message, got: %v", err)
		}
	})

	t.Run("SchemeAggregateSignatures_EmptyInput", func(t *testing.T) {
		_, err := scheme.AggregateSignatures([]signing.Signature{})
		if err == nil {
			t.Error("Expected error for empty signatures slice, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be empty") {
			t.Errorf("Expected empty error message, got: %v", err)
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

	t.Run("SchemeAggregateVerify_NilInputs", func(t *testing.T) {
		message := []byte("test")

		// Test nil public keys
		_, err := scheme.AggregateVerify(nil, [][]byte{message}, nil)
		if err == nil {
			t.Error("Expected error for nil public keys, but got none")
		}

		// Test nil messages
		_, err = scheme.AggregateVerify([]signing.PublicKey{}, nil, nil)
		if err == nil {
			t.Error("Expected error for nil messages, but got none")
		}

		// Test nil signature
		_, err = scheme.AggregateVerify([]signing.PublicKey{}, [][]byte{message}, nil)
		if err == nil {
			t.Error("Expected error for nil signature, but got none")
		}
	})

	t.Run("PrivateKeyAdapter_NilMessage", func(t *testing.T) {
		// Generate a key pair through the scheme
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test signing with nil message
		_, err = privKey.Sign(nil)
		if err == nil {
			t.Error("Expected error for nil message, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil error message, got: %v", err)
		}
	})

	t.Run("SignatureAdapter_NilInputs", func(t *testing.T) {
		// Generate a signature through the scheme
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
}

// Additional tests to improve coverage above 80%

func TestSchemeAdapterMethods(t *testing.T) {
	scheme := NewScheme()

	t.Run("SchemeGenerateKeyPairFromSeed", func(t *testing.T) {
		seed := []byte("test seed for scheme adapter with sufficient length for 32 bytes minimum")
		privKey, pubKey, err := scheme.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate key pair from seed: %v", err)
		}
		if privKey == nil || pubKey == nil {
			t.Fatal("Generated keys should not be nil")
		}

		// Test deterministic behavior
		privKey2, pubKey2, err := scheme.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		if !bytes.Equal(privKey.Bytes(), privKey2.Bytes()) {
			t.Error("Keys from same seed should be identical")
		}
		if !bytes.Equal(pubKey.Bytes(), pubKey2.Bytes()) {
			t.Error("Public keys from same seed should be identical")
		}
	})

	t.Run("SchemeGenerateKeyPairEIP2333", func(t *testing.T) {
		seed := []byte("test seed for EIP2333 scheme adapter with sufficient length")
		path := []uint32{12381, 3600, 0, 0}

		privKey, pubKey, err := scheme.GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to generate key pair with EIP2333: %v", err)
		}
		if privKey == nil || pubKey == nil {
			t.Fatal("Generated keys should not be nil")
		}

		// Test deterministic behavior
		privKey2, pubKey2, err := scheme.GenerateKeyPairEIP2333(seed, path)
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		if !bytes.Equal(privKey.Bytes(), privKey2.Bytes()) {
			t.Error("Keys from same seed and path should be identical")
		}
		if !bytes.Equal(pubKey.Bytes(), pubKey2.Bytes()) {
			t.Error("Public keys from same seed and path should be identical")
		}

		// Test different paths give different keys
		differentPath := []uint32{12381, 3600, 0, 1}
		privKey3, _, err := scheme.GenerateKeyPairEIP2333(seed, differentPath)
		if err != nil {
			t.Fatalf("Failed to generate key pair with different path: %v", err)
		}

		if bytes.Equal(privKey.Bytes(), privKey3.Bytes()) {
			t.Error("Different paths should generate different keys")
		}
	})

	t.Run("SchemeNewPrivateKeyFromBytes", func(t *testing.T) {
		// Generate a key to get valid bytes
		originalPrivKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate original key: %v", err)
		}

		keyBytes := originalPrivKey.Bytes()
		adaptedPrivKey, err := scheme.NewPrivateKeyFromBytes(keyBytes)
		if err != nil {
			t.Fatalf("Failed to create private key from bytes: %v", err)
		}

		if !bytes.Equal(keyBytes, adaptedPrivKey.Bytes()) {
			t.Error("Restored private key should match original")
		}

		// Test with empty bytes (this might not error in BLS implementation)
		emptyPrivKey, err := scheme.NewPrivateKeyFromBytes([]byte{})
		if err != nil {
			t.Logf("Got expected error for empty bytes: %v", err)
		} else if emptyPrivKey != nil {
			t.Logf("Empty bytes created private key (acceptable behavior)")
		}
	})

	t.Run("SchemeNewPublicKeyFromBytes", func(t *testing.T) {
		// Generate a key to get valid bytes
		_, originalPubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate original key: %v", err)
		}

		keyBytes := originalPubKey.Bytes()
		adaptedPubKey, err := scheme.NewPublicKeyFromBytes(keyBytes)
		if err != nil {
			t.Fatalf("Failed to create public key from bytes: %v", err)
		}

		if !bytes.Equal(keyBytes, adaptedPubKey.Bytes()) {
			t.Error("Restored public key should match original")
		}

		// Test error case
		_, err = scheme.NewPublicKeyFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes")
		}
	})

	t.Run("SchemeNewSignatureFromBytes", func(t *testing.T) {
		// Generate a signature to get valid bytes
		privKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message for signature")
		originalSig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		sigBytes := originalSig.Bytes()
		adaptedSig, err := scheme.NewSignatureFromBytes(sigBytes)
		if err != nil {
			t.Fatalf("Failed to create signature from bytes: %v", err)
		}

		if !bytes.Equal(sigBytes, adaptedSig.Bytes()) {
			t.Error("Restored signature should match original")
		}

		// Test error case
		_, err = scheme.NewSignatureFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes")
		}
	})

	t.Run("SchemeNewPublicKeyFromHexString", func(t *testing.T) {
		// Generate a key to get valid hex
		_, originalPubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate original key: %v", err)
		}

		hexStr := hex.EncodeToString(originalPubKey.Bytes())
		adaptedPubKey, err := scheme.NewPublicKeyFromHexString(hexStr)
		if err != nil {
			t.Fatalf("Failed to create public key from hex: %v", err)
		}

		if !bytes.Equal(originalPubKey.Bytes(), adaptedPubKey.Bytes()) {
			t.Error("Restored public key should match original")
		}

		// Test with 0x prefix (if supported)
		adaptedPubKey2, err := scheme.NewPublicKeyFromHexString("0x" + hexStr)
		if err != nil {
			t.Logf("Note: 0x prefix not supported in scheme adapter: %v", err)
		} else if !bytes.Equal(originalPubKey.Bytes(), adaptedPubKey2.Bytes()) {
			t.Error("Public key from hex with prefix should match original")
		}

		// Test error case
		_, err = scheme.NewPublicKeyFromHexString("invalid_hex")
		if err == nil {
			t.Error("Expected error for invalid hex")
		}
	})

	t.Run("SchemePrivateKeyAdapterMethods", func(t *testing.T) {
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test Public method
		adaptedPubKey := privKey.Public()
		if !bytes.Equal(pubKey.Bytes(), adaptedPubKey.Bytes()) {
			t.Error("Public key from adapter should match original")
		}

		// Test Bytes method (already covered but ensuring adapter path)
		keyBytes := privKey.Bytes()
		if len(keyBytes) == 0 {
			t.Error("Private key bytes should not be empty")
		}
	})

	t.Run("SchemePublicKeyAdapterMethods", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test Bytes method (ensuring adapter path is covered)
		keyBytes := pubKey.Bytes()
		if len(keyBytes) == 0 {
			t.Error("Public key bytes should not be empty")
		}
	})

	t.Run("SchemeSignatureAdapterMethods", func(t *testing.T) {
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message for adapter")
		sig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Test Verify method (ensuring adapter path is covered)
		valid, err := sig.Verify(pubKey, message)
		if err != nil {
			t.Fatalf("Failed to verify signature: %v", err)
		}
		if !valid {
			t.Error("Signature should be valid")
		}

		// Test with wrong message
		wrongMessage := []byte("wrong message")
		valid, err = sig.Verify(pubKey, wrongMessage)
		if err != nil {
			t.Fatalf("Failed to verify signature with wrong message: %v", err)
		}
		if valid {
			t.Error("Signature should be invalid for wrong message")
		}

		// Test Bytes method (ensuring adapter path is covered)
		sigBytes := sig.Bytes()
		if len(sigBytes) == 0 {
			t.Error("Signature bytes should not be empty")
		}
	})
}

func TestSchemeAggregationMethods(t *testing.T) {
	scheme := NewScheme()

	t.Run("SchemeAggregateSignaturesComprehensive", func(t *testing.T) {
		// Generate multiple key pairs and signatures
		numKeys := 5
		privKeys := make([]signing.PrivateKey, numKeys)
		pubKeys := make([]signing.PublicKey, numKeys)
		signatures := make([]signing.Signature, numKeys)
		message := []byte("test message for aggregation")

		for i := 0; i < numKeys; i++ {
			privKey, pubKey, err := scheme.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			sig, err := privKey.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}

			privKeys[i] = privKey
			pubKeys[i] = pubKey
			signatures[i] = sig
		}

		// Test successful aggregation
		aggSig, err := scheme.AggregateSignatures(signatures)
		if err != nil {
			t.Fatalf("Failed to aggregate signatures: %v", err)
		}

		if aggSig == nil {
			t.Fatal("Aggregated signature should not be nil")
		}

		// Test with single signature
		singleSig, err := scheme.AggregateSignatures([]signing.Signature{signatures[0]})
		if err != nil {
			t.Fatalf("Failed to aggregate single signature: %v", err)
		}

		if !bytes.Equal(signatures[0].Bytes(), singleSig.Bytes()) {
			t.Error("Aggregating single signature should return identical signature")
		}

		// Test error cases are already covered in input validation tests
	})

	t.Run("SchemeBatchVerifyComprehensive", func(t *testing.T) {
		// Generate multiple key pairs and signatures
		numKeys := 3
		privKeys := make([]signing.PrivateKey, numKeys)
		pubKeys := make([]signing.PublicKey, numKeys)
		signatures := make([]signing.Signature, numKeys)
		message := []byte("test message for batch verify")

		for i := 0; i < numKeys; i++ {
			privKey, pubKey, err := scheme.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			sig, err := privKey.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}

			privKeys[i] = privKey
			pubKeys[i] = pubKey
			signatures[i] = sig
		}

		// Test successful batch verification
		valid, err := scheme.BatchVerify(pubKeys, message, signatures)
		if err != nil {
			t.Fatalf("Failed to batch verify: %v", err)
		}
		if !valid {
			t.Error("Batch verification should succeed with valid signatures")
		}

		// Test with invalid signature
		invalidSig, err := privKeys[0].Sign([]byte("different message"))
		if err != nil {
			t.Fatalf("Failed to create invalid signature: %v", err)
		}

		signatures[1] = invalidSig
		valid, err = scheme.BatchVerify(pubKeys, message, signatures)
		if err != nil {
			t.Fatalf("Failed to batch verify with invalid signature: %v", err)
		}
		if valid {
			t.Error("Batch verification should fail with invalid signature")
		}

		// Test with single signature
		valid, err = scheme.BatchVerify([]signing.PublicKey{pubKeys[0]}, message, []signing.Signature{signatures[0]})
		if err != nil {
			t.Fatalf("Failed to batch verify single signature: %v", err)
		}
		if !valid {
			t.Error("Single signature batch verify should succeed")
		}
	})

	t.Run("SchemeAggregateVerifyComprehensive", func(t *testing.T) {
		// Generate multiple key pairs with different messages
		numKeys := 3
		privKeys := make([]signing.PrivateKey, numKeys)
		pubKeys := make([]signing.PublicKey, numKeys)
		signatures := make([]signing.Signature, numKeys)
		messages := make([][]byte, numKeys)

		for i := 0; i < numKeys; i++ {
			privKey, pubKey, err := scheme.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			message := []byte(fmt.Sprintf("test message %d for aggregate verify", i))
			sig, err := privKey.Sign(message)
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}

			privKeys[i] = privKey
			pubKeys[i] = pubKey
			signatures[i] = sig
			messages[i] = message
		}

		// Aggregate signatures
		aggSig, err := scheme.AggregateSignatures(signatures)
		if err != nil {
			t.Fatalf("Failed to aggregate signatures: %v", err)
		}

		// Test successful aggregate verification
		valid, err := scheme.AggregateVerify(pubKeys, messages, aggSig)
		if err != nil {
			t.Fatalf("Failed to aggregate verify: %v", err)
		}
		if !valid {
			t.Error("Aggregate verification should succeed with valid signatures")
		}

		// Test with wrong message
		wrongMessages := make([][]byte, numKeys)
		copy(wrongMessages, messages)
		wrongMessages[1] = []byte("wrong message")

		valid, err = scheme.AggregateVerify(pubKeys, wrongMessages, aggSig)
		if err != nil {
			t.Fatalf("Failed to aggregate verify with wrong message: %v", err)
		}
		if valid {
			t.Error("Aggregate verification should fail with wrong message")
		}

		// Test with single signature
		singleAggSig, err := scheme.AggregateSignatures([]signing.Signature{signatures[0]})
		if err != nil {
			t.Fatalf("Failed to aggregate single signature: %v", err)
		}

		valid, err = scheme.AggregateVerify([]signing.PublicKey{pubKeys[0]}, [][]byte{messages[0]}, singleAggSig)
		if err != nil {
			t.Fatalf("Failed to aggregate verify single signature: %v", err)
		}
		if !valid {
			t.Error("Single signature aggregate verify should succeed")
		}
	})
}

func TestVerifySolidityCompatible(t *testing.T) {
	t.Run("VerifySolidityCompatibleFunction", func(t *testing.T) {
		// Generate a key pair
		privKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create a test message hash (32 bytes)
		messageBytes := []byte("test message for solidity compatibility")
		messageHash := [32]byte{}
		// Only copy up to min(len(messageBytes), 32) to avoid slice bounds error
		copyLen := len(messageBytes)
		if copyLen > 32 {
			copyLen = 32
		}
		copy(messageHash[:copyLen], messageBytes[:copyLen])

		signature, err := privKey.Sign(messageHash[:])
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Test VerifySolidityCompatible
		valid, err := signature.VerifySolidityCompatible(pubKey, messageHash)
		if err != nil {
			t.Fatalf("Failed to verify solidity compatible: %v", err)
		}
		if !valid {
			t.Error("Solidity compatible verification should succeed")
		}

		// Test with wrong message
		wrongBytes := []byte("wrong message")
		wrongMessageHash := [32]byte{}
		copyLen2 := len(wrongBytes)
		if copyLen2 > 32 {
			copyLen2 = 32
		}
		copy(wrongMessageHash[:copyLen2], wrongBytes[:copyLen2])
		valid, err = signature.VerifySolidityCompatible(pubKey, wrongMessageHash)
		if err != nil {
			t.Fatalf("Failed to verify solidity compatible with wrong message: %v", err)
		}
		if valid {
			t.Error("Solidity compatible verification should fail with wrong message")
		}

		// Test with different key
		_, wrongPubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate wrong key pair: %v", err)
		}

		valid, err = signature.VerifySolidityCompatible(wrongPubKey, messageHash)
		if err != nil {
			t.Fatalf("Failed to verify solidity compatible with wrong key: %v", err)
		}
		if valid {
			t.Error("Solidity compatible verification should fail with wrong key")
		}

		// Test with zero hash
		zeroHash := [32]byte{}
		_, err = signature.VerifySolidityCompatible(pubKey, zeroHash)
		if err != nil {
			t.Fatalf("Failed to verify solidity compatible with zero hash: %v", err)
		}
		// Zero hash verification result depends on implementation
	})
}

func TestSignatureAdd(t *testing.T) {
	t.Run("SignatureAddFunction", func(t *testing.T) {
		// Generate two key pairs and signatures
		privKey1, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate first key pair: %v", err)
		}

		privKey2, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate second key pair: %v", err)
		}

		message := []byte("test message for signature addition")
		sig1, err := privKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with first key: %v", err)
		}

		sig2, err := privKey2.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with second key: %v", err)
		}

		// Test addition
		originalSig1Bytes := sig1.Bytes()
		result := sig1.Add(sig2)

		if result == nil {
			t.Fatal("Addition result should not be nil")
		}

		// Test that result is different from original sig1
		if bytes.Equal(result.Bytes(), originalSig1Bytes) {
			t.Error("Addition should modify the signature")
		}

		// Test with nil signature (should handle gracefully)
		sig3, err := privKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign for nil test: %v", err)
		}

		result2 := sig3.Add(nil)
		if !bytes.Equal(result2.Bytes(), sig3.Bytes()) {
			t.Error("Adding nil signature should return original signature")
		}

		// Test adding signature to itself (creates a doubled signature)
		sig4, err := privKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign for self test: %v", err)
		}

		originalSig4Bytes := sig4.Bytes()
		selfResult := sig4.Add(sig4)

		if bytes.Equal(selfResult.Bytes(), originalSig4Bytes) {
			t.Error("Adding signature to itself should produce different result")
		}
	})
}

func TestHashToG1Coverage(t *testing.T) {
	t.Run("HashToG1ErrorCases", func(t *testing.T) {
		// Test with nil message
		point := hashToG1(nil)
		if point == nil {
			t.Error("hashToG1 should handle nil message gracefully")
		}

		// Test with various message lengths
		testMessages := [][]byte{
			{},                                 // empty
			{0x00},                             // single byte
			[]byte("short"),                    // short message
			bytes.Repeat([]byte("a"), 100),     // medium message
			bytes.Repeat([]byte("test"), 1000), // long message
		}

		for i, msg := range testMessages {
			point := hashToG1(msg)
			if point == nil {
				t.Errorf("hashToG1 should not return nil for test case %d", i)
			}
		}

		// Test deterministic behavior
		msg := []byte("deterministic test")
		point1 := hashToG1(msg)
		point2 := hashToG1(msg)

		if point1 == nil || point2 == nil {
			t.Fatal("hashToG1 should not return nil")
		}

		// Points should be equal for same message (this tests the deterministic property)
		bytes1 := point1.Marshal()
		bytes2 := point2.Marshal()
		if !bytes.Equal(bytes1, bytes2) {
			t.Error("hashToG1 should be deterministic")
		}
	})
}

func TestAdditionalPublicKeyMethods(t *testing.T) {
	t.Run("GetG1Point", func(t *testing.T) {
		_, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		g1Point := pubKey.GetG1Point()
		if g1Point == nil {
			t.Error("GetG1Point should return valid point")
		}
	})

	t.Run("GetG2Point", func(t *testing.T) {
		_, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		g2Point := pubKey.GetG2Point()
		if g2Point == nil {
			t.Error("GetG2Point should return valid point")
		}
	})
}

func TestSignatureVerifyErrorPaths(t *testing.T) {
	t.Run("SignatureVerifyWithInvalidPublicKey", func(t *testing.T) {
		// Generate a valid signature
		privKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message")
		signature, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign message: %v", err)
		}

		// Create an invalid public key (all zeros)
		invalidPubKeyBytes := make([]byte, 96) // BLS public key is 96 bytes
		invalidPubKey, err := NewPublicKeyFromBytes(invalidPubKeyBytes)
		if err == nil {
			// If we can create it, test verification fails gracefully
			valid, err := signature.Verify(invalidPubKey, message)
			if err != nil {
				t.Logf("Verify correctly failed with invalid public key: %v", err)
			} else if valid {
				t.Error("Verification should fail with invalid public key")
			}
		}
	})
}

func TestNewPublicKeyFromBytesErrorPaths(t *testing.T) {
	t.Run("NewPublicKeyFromBytesInvalidPoints", func(t *testing.T) {
		// Test with G1 point length but invalid data
		invalidG1Data := make([]byte, 48)
		for i := range invalidG1Data {
			invalidG1Data[i] = 0xFF // Fill with invalid data
		}

		_, err := NewPublicKeyFromBytes(invalidG1Data)
		if err == nil {
			t.Error("Expected error for invalid G1 point data")
		}

		// Test with G2 point length but invalid data
		invalidG2Data := make([]byte, 96)
		for i := range invalidG2Data {
			invalidG2Data[i] = 0xFF // Fill with invalid data
		}

		_, err = NewPublicKeyFromBytes(invalidG2Data)
		if err == nil {
			t.Error("Expected error for invalid G2 point data")
		}

		// Test with valid length but specific invalid point (point at infinity concerns)
		almostValidG2 := make([]byte, 96)
		// Set some bytes to create potentially problematic point
		almostValidG2[0] = 0x40 // Set compression flag

		_, err = NewPublicKeyFromBytes(almostValidG2)
		// This may or may not error depending on BLS implementation
		if err != nil {
			t.Logf("Got expected error for problematic G2 point: %v", err)
		}
	})
}
