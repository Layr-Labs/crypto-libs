package bls381

import (
	"bytes"
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
			t.Errorf("Expected no error for empty message, but got: %v", err)
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
		if !strings.Contains(err.Error(), "cannot be nil") {
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
