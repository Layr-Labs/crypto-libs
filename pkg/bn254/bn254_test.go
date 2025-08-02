package bn254

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

func Test_BN254(t *testing.T) {
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

	t.Run("EIP2333NotSupported", func(t *testing.T) {
		// Test using the scheme
		scheme := NewScheme()
		seed := []byte("a seed phrase that is at least 32 bytes long")
		path := []uint32{3, 14, 15, 92}

		// Attempt to create a key pair using EIP-2333
		_, _, err := scheme.GenerateKeyPairEIP2333(seed, path)

		// Should return an unsupported operation error
		if err == nil {
			t.Error("Expected EIP-2333 to be unsupported, but no error was returned")
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
		bn254PrivKey := privKey.(*privateKeyAdapter).pk

		// Test hex conversion
		hexString, err := bn254PrivKey.ToHex()
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
			point, err := hashToG1(tt.message)
			if err != nil {
				t.Fatalf("hashToG1 failed: %v", err)
			}

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

func TestPublicKeyG1G2(t *testing.T) {
	// Generate a key pair
	sk, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Get both G1 and G2 points
	g1Point := pk.GetG1Point()
	g2Point := pk.GetG2Point()

	// Verify G1 point
	if g1Point == nil {
		t.Fatal("G1 point is nil")
	}
	if !g1Point.IsOnCurve() {
		t.Fatal("G1 point is not on the curve")
	}
	if !g1Point.IsInSubGroup() {
		t.Fatal("G1 point is not in the subgroup")
	}

	// Verify G2 point
	if g2Point == nil {
		t.Fatal("G2 point is nil")
	}
	if !g2Point.IsOnCurve() {
		t.Fatal("G2 point is not on the curve")
	}
	if !g2Point.IsInSubGroup() {
		t.Fatal("G2 point is not in the subgroup")
	}

	// Verify that both points correspond to the same private key
	g1Check := new(bn254.G1Affine).ScalarMultiplication(&g1Gen, sk.scalar)
	g2Check := new(bn254.G2Affine).ScalarMultiplication(&g2Gen, sk.scalar)

	if !g1Point.Equal(g1Check) {
		t.Fatal("G1 point does not match private key")
	}
	if !g2Point.Equal(g2Check) {
		t.Fatal("G2 point does not match private key")
	}
}

func TestPublicKeyFromBytes(t *testing.T) {
	// Generate a key pair
	_, pk, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test G2 point bytes
	g2Bytes := pk.GetG2Point().Marshal()
	pkFromG2, err := NewPublicKeyFromBytes(g2Bytes)
	if err != nil {
		t.Fatalf("Failed to create public key from G2 bytes: %v", err)
	}
	if !pkFromG2.GetG2Point().Equal(pk.GetG2Point()) {
		t.Fatal("G2 point mismatch after unmarshaling")
	}

	// Test G1 point bytes
	g1Bytes := pk.GetG1Point().Marshal()
	pkFromG1, err := NewPublicKeyFromBytes(g1Bytes)
	if err != nil {
		t.Fatalf("Failed to create public key from G1 bytes: %v", err)
	}
	if !pkFromG1.GetG1Point().Equal(pk.GetG1Point()) {
		t.Fatal("G1 point mismatch after unmarshaling")
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

func TestPrecompileCompatibility(t *testing.T) {
	t.Run("G1PointFormat", func(t *testing.T) {
		// Test G1 point serialization
		g1Point := NewG1Point(big.NewInt(1), big.NewInt(2))
		precompileFormat, err := g1Point.ToPrecompileFormat()
		if err != nil {
			t.Fatalf("Failed to convert G1 point to precompile format: %v", err)
		}
		if len(precompileFormat) != G1PointSize {
			t.Errorf("G1 point precompile format should be %d bytes, got %d", G1PointSize, len(precompileFormat))
		}

		// Test round-trip conversion
		recoveredG1, err := G1PointFromPrecompileFormat(precompileFormat)
		if err != nil {
			t.Fatalf("Failed to recover G1 point: %v", err)
		}
		if !recoveredG1.G1Affine.Equal(g1Point.G1Affine) {
			t.Error("G1 point mismatch after round-trip conversion")
		}
	})

	t.Run("G2PointFormat", func(t *testing.T) {
		// Create a valid G2 point by scalar multiplication with the generator
		scalar := big.NewInt(12345)
		g2Point := &G2Point{new(bn254.G2Affine).ScalarMultiplication(&g2Gen, scalar)}

		precompileFormat, err := g2Point.ToPrecompileFormat()
		if err != nil {
			t.Fatalf("Failed to convert G2 point to precompile format: %v", err)
		}
		if len(precompileFormat) != G2PointSize {
			t.Errorf("G2 point precompile format should be %d bytes, got %d", G2PointSize, len(precompileFormat))
		}

		// Test round-trip conversion
		recoveredG2, err := G2PointFromPrecompileFormat(precompileFormat)
		if err != nil {
			t.Fatalf("Failed to recover G2 point: %v", err)
		}
		if !recoveredG2.G2Affine.Equal(g2Point.G2Affine) {
			t.Error("G2 point mismatch after round-trip conversion")
		}
	})

	t.Run("InvalidPointFormats", func(t *testing.T) {
		// Test invalid G1 point format
		_, err := G1PointFromPrecompileFormat(make([]byte, G1PointSize-1))
		if err == nil {
			t.Error("Expected error for invalid G1 point length")
		}

		// Test invalid G2 point format
		_, err = G2PointFromPrecompileFormat(make([]byte, G2PointSize-1))
		if err == nil {
			t.Error("Expected error for invalid G2 point length")
		}
	})

	t.Run("FieldOrderValidation", func(t *testing.T) {
		// Test valid field order
		valid := ValidateFieldOrder(big.NewInt(1))
		if !valid {
			t.Error("Expected valid field order for small number")
		}

		// Test invalid field order
		invalid := ValidateFieldOrder(new(big.Int).Add(FieldModulus, big.NewInt(1)))
		if invalid {
			t.Error("Expected invalid field order for number larger than modulus")
		}
	})
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

func TestInputValidation_SolidityCompatibleFunctions(t *testing.T) {
	// Generate a valid private key for testing
	privateKey, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	t.Run("SignSolidityCompatible_ZeroHash", func(t *testing.T) {
		var zeroHash [32]byte
		_, err := privateKey.SignSolidityCompatible(zeroHash)
		if err != nil {
			t.Errorf("Expected no error for zero hash, but got: %v", err)
		}
	})

	t.Run("SignSolidityCompatible_RandomHash", func(t *testing.T) {
		var randomHash [32]byte
		for i := range randomHash {
			randomHash[i] = byte(i)
		}
		_, err := privateKey.SignSolidityCompatible(randomHash)
		if err != nil {
			t.Errorf("Expected no error for random hash, but got: %v", err)
		}
	})

	t.Run("SignSolidityCompatible_MaxHash", func(t *testing.T) {
		var maxHash [32]byte
		for i := range maxHash {
			maxHash[i] = 0xFF
		}
		_, err := privateKey.SignSolidityCompatible(maxHash)
		if err != nil {
			t.Errorf("Expected no error for max hash, but got: %v", err)
		}
	})

	t.Run("VerifySolidityCompatible", func(t *testing.T) {
		var testHash [32]byte
		for i := range testHash {
			testHash[i] = byte(i % 256)
		}

		signature, err := privateKey.SignSolidityCompatible(testHash)
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		valid, err := signature.VerifySolidityCompatible(publicKey, testHash)
		if err != nil {
			t.Errorf("Expected no error for verification, but got: %v", err)
		}
		if !valid {
			t.Error("Expected signature to be valid")
		}
	})

	t.Run("BatchVerifySolidityCompatible_EmptySlices", func(t *testing.T) {
		var testHash [32]byte
		_, err := BatchVerifySolidityCompatible([]*PublicKey{}, testHash, []*Signature{})
		if err == nil {
			t.Error("Expected error for empty slices, but got none")
		}
	})

	t.Run("BatchVerifySolidityCompatible_MismatchedLengths", func(t *testing.T) {
		var testHash [32]byte
		signature, err := privateKey.SignSolidityCompatible(testHash)
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		_, err = BatchVerifySolidityCompatible([]*PublicKey{publicKey, publicKey}, testHash, []*Signature{signature})
		if err == nil {
			t.Error("Expected error for mismatched lengths, but got none")
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
		// Test with G1 point length - all zeros might be valid (point at infinity)
		// Use invalid data that's definitely not a valid G1 point
		g1Data := make([]byte, 64)
		for i := range g1Data {
			g1Data[i] = 0xFF
		}
		_, err := NewPublicKeyFromBytes(g1Data)
		if err == nil {
			t.Error("Expected error for invalid G1 point data, but got none")
		}
	})

	t.Run("G2PointLength", func(t *testing.T) {
		// Test with G2 point length - all zeros is point at infinity and might be valid
		g2Data := make([]byte, 128)
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
		wrongData := make([]byte, 64) // Correct length but invalid format
		for i := range wrongData {
			wrongData[i] = 0xFF
		}
		_, err := NewSignatureFromBytes(wrongData)
		if err == nil {
			t.Error("Expected error for wrong format data, but got none")
		}
	})

	t.Run("AllZeros", func(t *testing.T) {
		// All zeros might be valid (point at infinity) for some curve implementations
		// Use invalid data that's definitely not a valid signature
		zeros := make([]byte, 64)
		for i := range zeros {
			zeros[i] = 0xFF
		}
		_, err := NewSignatureFromBytes(zeros)
		if err == nil {
			t.Error("Expected error for invalid signature data, but got none")
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

func TestInputValidation_G1PointOperations(t *testing.T) {
	t.Run("NewG1Point_NilInputs", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil inputs, but got none")
			}
		}()
		_ = NewG1Point(nil, nil)
	})

	t.Run("NewG1Point_ValidInputs", func(t *testing.T) {
		x := big.NewInt(1)
		y := big.NewInt(1)
		point := NewG1Point(x, y)
		if point == nil {
			t.Error("Expected non-nil G1 point")
		}
	})

	t.Run("G1Point_Add_NilInput", func(t *testing.T) {
		point := NewZeroG1Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil input to Add, but got none")
			}
		}()
		_ = point.Add(nil)
	})

	t.Run("G1Point_Sub_NilInput", func(t *testing.T) {
		point := NewZeroG1Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil input to Sub, but got none")
			}
		}()
		_ = point.Sub(nil)
	})

	t.Run("G1PointFromPrecompileFormat_NilData", func(t *testing.T) {
		_, err := G1PointFromPrecompileFormat(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
	})

	t.Run("G1PointFromPrecompileFormat_InvalidLength", func(t *testing.T) {
		data := make([]byte, 32) // Should be 64 bytes
		_, err := G1PointFromPrecompileFormat(data)
		if err == nil {
			t.Error("Expected error for invalid length, but got none")
		}
	})

	t.Run("G1PointFromPrecompileFormat_ValidLength", func(t *testing.T) {
		// All zeros might be valid (point at infinity), use invalid data
		data := make([]byte, G1PointSize) // 64 bytes
		for i := range data {
			data[i] = 0xFF
		}
		_, err := G1PointFromPrecompileFormat(data)
		if err == nil {
			t.Error("Expected error for invalid point data, but got none")
		}
	})

	t.Run("G1Point_AddPublicKey_NilPublicKey", func(t *testing.T) {
		point := NewZeroG1Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key, but got none")
			}
		}()
		_ = point.AddPublicKey(nil)
	})
}

func TestInputValidation_G2PointOperations(t *testing.T) {
	t.Run("NewG2Point_NilInputs", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil inputs, but got none")
			}
		}()
		_ = NewG2Point(nil, nil, nil, nil)
	})

	t.Run("NewG2Point_ValidInputs", func(t *testing.T) {
		x0, x1, y0, y1 := big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)
		point := NewG2Point(x0, x1, y0, y1)
		if point == nil {
			t.Error("Expected non-nil G2 point")
		}
	})

	t.Run("G2Point_Add_NilInput", func(t *testing.T) {
		point := NewZeroG2Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil input to Add, but got none")
			}
		}()
		_ = point.Add(nil)
	})

	t.Run("G2Point_Sub_NilInput", func(t *testing.T) {
		point := NewZeroG2Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil input to Sub, but got none")
			}
		}()
		_ = point.Sub(nil)
	})

	t.Run("G2PointFromPrecompileFormat_NilData", func(t *testing.T) {
		_, err := G2PointFromPrecompileFormat(nil)
		if err == nil {
			t.Error("Expected error for nil data, but got none")
		}
	})

	t.Run("G2PointFromPrecompileFormat_InvalidLength", func(t *testing.T) {
		data := make([]byte, 64) // Should be 128 bytes
		_, err := G2PointFromPrecompileFormat(data)
		if err == nil {
			t.Error("Expected error for invalid length, but got none")
		}
	})

	t.Run("G2PointFromPrecompileFormat_ValidLength", func(t *testing.T) {
		// All zeros might be valid (point at infinity), use invalid data
		data := make([]byte, G2PointSize) // 128 bytes
		for i := range data {
			data[i] = 0xFF
		}
		_, err := G2PointFromPrecompileFormat(data)
		if err == nil {
			t.Error("Expected error for invalid point data, but got none")
		}
	})

	t.Run("G2Point_AddPublicKey_NilPublicKey", func(t *testing.T) {
		point := NewZeroG2Point()
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key, but got none")
			}
		}()
		_ = point.AddPublicKey(nil)
	})
}

func TestInputValidation_NewPublicKeyFromSolidity(t *testing.T) {
	t.Run("NilG1Point", func(t *testing.T) {
		g2 := &SolidityBN254G2Point{
			X: [2]*big.Int{big.NewInt(1), big.NewInt(1)},
			Y: [2]*big.Int{big.NewInt(1), big.NewInt(1)},
		}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil G1 point, but got none")
			}
		}()
		_, _ = NewPublicKeyFromSolidity(nil, g2)
	})

	t.Run("NilG2Point", func(t *testing.T) {
		// Use zero point (point at infinity) which should be in the subgroup
		g1 := &SolidityBN254G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil G2 point, but got none")
			}
		}()
		_, _ = NewPublicKeyFromSolidity(g1, nil)
	})

	t.Run("BothNil", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for both nil points, but got none")
			}
		}()
		_, _ = NewPublicKeyFromSolidity(nil, nil)
	})

	t.Run("InvalidG1Point", func(t *testing.T) {
		// Create invalid G1 point (not on curve)
		g1 := &SolidityBN254G1Point{
			X: big.NewInt(1),
			Y: big.NewInt(2), // This will not be on the curve
		}
		g2 := &SolidityBN254G2Point{
			X: [2]*big.Int{big.NewInt(0), big.NewInt(0)},
			Y: [2]*big.Int{big.NewInt(1), big.NewInt(0)},
		}
		_, err := NewPublicKeyFromSolidity(g1, g2)
		if err == nil {
			t.Error("Expected error for invalid G1 point, but got none")
		}
	})

	t.Run("InvalidG2Point", func(t *testing.T) {
		// Start with zero G1 point (valid point at infinity)
		g1 := &SolidityBN254G1Point{X: big.NewInt(0), Y: big.NewInt(0)}
		// Create invalid G2 point
		g2 := &SolidityBN254G2Point{
			X: [2]*big.Int{big.NewInt(1), big.NewInt(1)},
			Y: [2]*big.Int{big.NewInt(1), big.NewInt(1)}, // This will not be on the curve
		}
		_, err := NewPublicKeyFromSolidity(g1, g2)
		if err == nil {
			t.Error("Expected error for invalid G2 point, but got none")
		}
	})
}

func TestInputValidation_AggregatePublicKeys(t *testing.T) {
	// Generate valid test data
	_, publicKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair for testing: %v", err)
	}

	t.Run("NilPublicKeys", func(t *testing.T) {
		_, err := AggregatePublicKeys(nil)
		if err == nil {
			t.Error("Expected error for nil public keys slice, but got none")
		}
	})

	t.Run("EmptyPublicKeys", func(t *testing.T) {
		_, err := AggregatePublicKeys([]*PublicKey{})
		if err == nil {
			t.Error("Expected error for empty public keys slice, but got none")
		}
	})

	t.Run("NilPublicKeyInSlice", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil public key in slice, but got none")
			}
		}()
		_, _ = AggregatePublicKeys([]*PublicKey{publicKey, nil, publicKey})
	})

	t.Run("SinglePublicKey", func(t *testing.T) {
		_, err := AggregatePublicKeys([]*PublicKey{publicKey})
		if err != nil {
			t.Errorf("Expected no error for single public key, but got: %v", err)
		}
	})

	t.Run("ManyPublicKeys", func(t *testing.T) {
		publicKeys := make([]*PublicKey, 50)
		for i := range publicKeys {
			publicKeys[i] = publicKey
		}
		_, err := AggregatePublicKeys(publicKeys)
		if err != nil {
			t.Errorf("Expected no error for many public keys, but got: %v", err)
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

	t.Run("SignG1Point_NilHashPoint", func(t *testing.T) {
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil hash point, but got none")
			}
		}()
		_, _ = privateKey.SignG1Point(nil)
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

	t.Run("GetG1Point_Nil", func(t *testing.T) {
		pk := &PublicKey{PointBytes: nil, g1Point: nil, g2Point: nil}
		g1Point := pk.GetG1Point()
		if g1Point != nil {
			t.Error("Expected nil G1 point for nil g1Point")
		}
	})

	t.Run("GetG2Point_Nil", func(t *testing.T) {
		pk := &PublicKey{PointBytes: nil, g1Point: nil, g2Point: nil}
		g2Point := pk.GetG2Point()
		if g2Point != nil {
			t.Error("Expected nil G2 point for nil g2Point")
		}
	})

	t.Run("Sub_NilOther", func(t *testing.T) {
		_, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// The Sub method gracefully handles nil by returning the original key
		result := pk.Sub(nil)
		if result != pk {
			t.Error("Expected same public key when subtracting nil, but got different")
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

	t.Run("Add_NilSignature", func(t *testing.T) {
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

	t.Run("Add_SignatureWithNilSig", func(t *testing.T) {
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

	t.Run("Sub_NilSignature", func(t *testing.T) {
		// Generate a valid signature for testing
		privateKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}
		sig, err := privateKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to generate signature: %v", err)
		}

		// Test subtracting nil signature
		result := sig.Sub(nil)
		if result != sig {
			t.Error("Expected same signature when subtracting nil")
		}
	})

	t.Run("GetG1Point_Nil", func(t *testing.T) {
		sig := &Signature{SigBytes: nil, sig: nil}
		g1Point := sig.GetG1Point()
		if g1Point != nil {
			t.Error("Expected nil G1 point for nil sig")
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

	t.Run("SignatureAdapter_NilAdapter", func(t *testing.T) {
		var nilAdapter *signatureAdapter = nil
		_, pubKey, _ := scheme.GenerateKeyPair()
		_, err := nilAdapter.Verify(pubKey, []byte("test"))
		if err == nil {
			t.Error("Expected error for nil signature adapter, but got none")
		}
		if !strings.Contains(err.Error(), "signature adapter cannot be nil") {
			t.Errorf("Expected signature adapter nil error message, got: %v", err)
		}
	})
}

func TestInputValidation_UtilityFunctions(t *testing.T) {
	t.Run("ValidateFieldOrder_NilInput", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nil input to ValidateFieldOrder, but got none")
			}
		}()
		_ = ValidateFieldOrder(nil)
	})

	t.Run("ValidateFieldOrder_ValidNumber", func(t *testing.T) {
		valid := ValidateFieldOrder(big.NewInt(100))
		if !valid {
			t.Error("Expected valid for small number")
		}
	})

	t.Run("ValidateFieldOrder_LargeNumber", func(t *testing.T) {
		// Create a number larger than the field modulus
		largeNum := new(big.Int).Add(FieldModulus, big.NewInt(1))
		valid := ValidateFieldOrder(largeNum)
		if valid {
			t.Error("Expected invalid for number larger than field modulus")
		}
	})

	t.Run("ValidateFieldOrder_ExactModulus", func(t *testing.T) {
		valid := ValidateFieldOrder(FieldModulus)
		if valid {
			t.Error("Expected invalid for exact field modulus")
		}
	})

	t.Run("SolidityHashToG1_ZeroHash", func(t *testing.T) {
		var zeroHash [32]byte
		point, err := SolidityHashToG1(zeroHash)
		if err != nil {
			t.Errorf("Expected no error for zero hash, but got: %v", err)
		}
		if point == nil {
			t.Error("Expected non-nil point for zero hash")
		}
	})

	t.Run("SolidityHashToG1_MaxHash", func(t *testing.T) {
		var maxHash [32]byte
		for i := range maxHash {
			maxHash[i] = 0xFF
		}
		point, err := SolidityHashToG1(maxHash)
		if err != nil {
			t.Errorf("Expected no error for max hash, but got: %v", err)
		}
		if point == nil {
			t.Error("Expected non-nil point for max hash")
		}
	})
}

// TestBatchVerifySolidityCompatible tests the BatchVerifySolidityCompatible function with various scenarios
func TestBatchVerifySolidityCompatible(t *testing.T) {
	// Generate test data
	numKeys := 3
	privateKeys := make([]*PrivateKey, numKeys)
	publicKeys := make([]*PublicKey, numKeys)
	signatures := make([]*Signature, numKeys)

	var testHash [32]byte
	for i := range testHash {
		testHash[i] = byte(i)
	}

	for i := 0; i < numKeys; i++ {
		var err error
		privateKeys[i], publicKeys[i], err = GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i, err)
		}

		signatures[i], err = privateKeys[i].SignSolidityCompatible(testHash)
		if err != nil {
			t.Fatalf("Failed to sign with key %d: %v", i, err)
		}
	}

	t.Run("ValidBatch", func(t *testing.T) {
		valid, err := BatchVerifySolidityCompatible(publicKeys, testHash, signatures)
		if err != nil {
			t.Fatalf("Expected no error for valid batch, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid batch verification")
		}
	})

	t.Run("SingleSignature", func(t *testing.T) {
		valid, err := BatchVerifySolidityCompatible(publicKeys[:1], testHash, signatures[:1])
		if err != nil {
			t.Fatalf("Expected no error for single signature, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid single signature verification")
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		// Create a wrong signature
		wrongPrivKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate wrong key: %v", err)
		}
		wrongSig, err := wrongPrivKey.SignSolidityCompatible(testHash)
		if err != nil {
			t.Fatalf("Failed to sign with wrong key: %v", err)
		}

		invalidSigs := []*Signature{wrongSig}
		valid, err := BatchVerifySolidityCompatible(publicKeys[:1], testHash, invalidSigs)
		if err != nil {
			t.Fatalf("Expected no error for invalid signature, but got: %v", err)
		}
		if valid {
			t.Error("Expected invalid signature verification")
		}
	})

	t.Run("DifferentHash", func(t *testing.T) {
		var differentHash [32]byte
		for i := range differentHash {
			differentHash[i] = byte(255 - i)
		}

		valid, err := BatchVerifySolidityCompatible(publicKeys, differentHash, signatures)
		if err != nil {
			t.Fatalf("Expected no error for different hash, but got: %v", err)
		}
		if valid {
			t.Error("Expected invalid verification with different hash")
		}
	})

	t.Run("ManySignatures", func(t *testing.T) {
		// Test with many signatures
		manyPrivKeys := make([]*PrivateKey, 10)
		manyPubKeys := make([]*PublicKey, 10)
		manySigs := make([]*Signature, 10)

		for i := 0; i < 10; i++ {
			var err error
			manyPrivKeys[i], manyPubKeys[i], err = GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			manySigs[i], err = manyPrivKeys[i].SignSolidityCompatible(testHash)
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}
		}

		valid, err := BatchVerifySolidityCompatible(manyPubKeys, testHash, manySigs)
		if err != nil {
			t.Fatalf("Expected no error for many signatures, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid verification with many signatures")
		}
	})
}

// TestSignatureOperations tests signature Add and Sub methods
func TestSignatureOperations(t *testing.T) {
	// Generate test signatures
	privKey1, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	privKey2, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	message := []byte("test message")
	sig1, err := privKey1.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with key 1: %v", err)
	}
	sig2, err := privKey2.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign with key 2: %v", err)
	}

	t.Run("Add_ValidSignatures", func(t *testing.T) {
		// Create copies to avoid modifying originals
		sig1Copy := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}
		sig2Copy := &Signature{
			sig:      sig2.sig,
			SigBytes: sig2.SigBytes,
		}

		result := sig1Copy.Add(sig2Copy)
		if result == nil {
			t.Error("Expected non-nil result from Add operation")
		}
		if result != sig1Copy {
			t.Error("Expected Add to return the same signature object")
		}
	})

	t.Run("Sub_ValidSignatures", func(t *testing.T) {
		// Create copies to avoid modifying originals
		sig1Copy := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}
		sig2Copy := &Signature{
			sig:      sig2.sig,
			SigBytes: sig2.SigBytes,
		}

		result := sig1Copy.Sub(sig2Copy)
		if result == nil {
			t.Error("Expected non-nil result from Sub operation")
		}
		if result != sig1Copy {
			t.Error("Expected Sub to return the same signature object")
		}
	})

	t.Run("Add_SameSignature", func(t *testing.T) {
		sig1Copy := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}
		sig1Copy2 := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}

		result := sig1Copy.Add(sig1Copy2)
		if result == nil {
			t.Error("Expected non-nil result from Add operation")
		}
	})

	t.Run("Sub_SameSignature", func(t *testing.T) {
		sig1Copy := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}
		sig1Copy2 := &Signature{
			sig:      sig1.sig,
			SigBytes: sig1.SigBytes,
		}

		result := sig1Copy.Sub(sig1Copy2)
		if result == nil {
			t.Error("Expected non-nil result from Sub operation")
		}
	})
}

// TestG1PointOperations tests G1 point operations with better coverage
func TestG1PointOperations(t *testing.T) {
	// Generate test data
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	t.Run("AddPublicKey_ValidPublicKey", func(t *testing.T) {
		point := NewZeroG1Point()
		result := point.AddPublicKey(pubKey)
		if result == nil {
			t.Error("Expected non-nil result from AddPublicKey")
		}
		if result != point {
			t.Error("Expected AddPublicKey to return the same point object")
		}
	})

	t.Run("AddPublicKey_PublicKeyWithNilG1Point", func(t *testing.T) {
		point := NewZeroG1Point()
		pubKeyWithNilG1 := &PublicKey{
			g1Point: nil,
			g2Point: pubKey.g2Point,
		}
		result := point.AddPublicKey(pubKeyWithNilG1)
		if result == nil {
			t.Error("Expected non-nil result from AddPublicKey")
		}
		if result != point {
			t.Error("Expected AddPublicKey to return the same point object")
		}
	})

	t.Run("ToPrecompileFormat_ValidPoint", func(t *testing.T) {
		// Create a valid point at infinity (zero point)
		point := NewZeroG1Point()
		_, err := point.ToPrecompileFormat()
		if err != nil {
			t.Errorf("Expected no error for valid point, but got: %v", err)
		}
	})

	t.Run("ToPrecompileFormat_InvalidPoint", func(t *testing.T) {
		// Create an invalid point (not in subgroup)
		point := NewG1Point(big.NewInt(1), big.NewInt(1))
		_, err := point.ToPrecompileFormat()
		if err == nil {
			t.Error("Expected error for invalid point, but got none")
		}
	})
}

// TestG2PointOperations tests G2 point operations with better coverage
func TestG2PointOperations(t *testing.T) {
	// Generate test data
	_, pubKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	t.Run("AddPublicKey_ValidPublicKey", func(t *testing.T) {
		point := NewZeroG2Point()
		result := point.AddPublicKey(pubKey)
		if result == nil {
			t.Error("Expected non-nil result from AddPublicKey")
		}
		if result != point {
			t.Error("Expected AddPublicKey to return the same point object")
		}
	})

	t.Run("AddPublicKey_PublicKeyWithNilG2Point", func(t *testing.T) {
		point := NewZeroG2Point()
		pubKeyWithNilG2 := &PublicKey{
			g1Point: pubKey.g1Point,
			g2Point: nil,
		}
		result := point.AddPublicKey(pubKeyWithNilG2)
		if result == nil {
			t.Error("Expected non-nil result from AddPublicKey")
		}
		if result != point {
			t.Error("Expected AddPublicKey to return the same point object")
		}
	})

	t.Run("ToPrecompileFormat_ValidPoint", func(t *testing.T) {
		// Create a valid point at infinity (zero point)
		point := NewZeroG2Point()
		_, err := point.ToPrecompileFormat()
		if err != nil {
			t.Errorf("Expected no error for valid point, but got: %v", err)
		}
	})

	t.Run("ToPrecompileFormat_InvalidPoint", func(t *testing.T) {
		// Create an invalid point (not in subgroup)
		point := NewG2Point(big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1))
		_, err := point.ToPrecompileFormat()
		if err == nil {
			t.Error("Expected error for invalid point, but got none")
		}
	})
}

// TestPublicKeyOperations tests public key operations with better coverage
func TestPublicKeyOperations(t *testing.T) {
	// Generate test data
	_, pubKey1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}
	_, pubKey2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	t.Run("Sub_ValidPublicKey", func(t *testing.T) {
		// Create a copy to avoid modifying original
		pubKey1Copy := &PublicKey{
			g1Point:    pubKey1.g1Point,
			g2Point:    pubKey1.g2Point,
			PointBytes: pubKey1.PointBytes,
		}

		result := pubKey1Copy.Sub(pubKey2)
		if result == nil {
			t.Error("Expected non-nil result from Sub operation")
		}
		if result != pubKey1Copy {
			t.Error("Expected Sub to return the same public key object")
		}
	})

	t.Run("Sub_PublicKeyWithNilG2Point", func(t *testing.T) {
		pubKey1Copy := &PublicKey{
			g1Point:    pubKey1.g1Point,
			g2Point:    pubKey1.g2Point,
			PointBytes: pubKey1.PointBytes,
		}

		pubKeyWithNilG2 := &PublicKey{
			g1Point: pubKey2.g1Point,
			g2Point: nil,
		}

		result := pubKey1Copy.Sub(pubKeyWithNilG2)
		if result == nil {
			t.Error("Expected non-nil result from Sub operation")
		}
		if result != pubKey1Copy {
			t.Error("Expected Sub to return the same public key object")
		}
	})

	t.Run("Sub_SamePublicKey", func(t *testing.T) {
		pubKey1Copy := &PublicKey{
			g1Point:    pubKey1.g1Point,
			g2Point:    pubKey1.g2Point,
			PointBytes: pubKey1.PointBytes,
		}
		pubKey1Copy2 := &PublicKey{
			g1Point:    pubKey1.g1Point,
			g2Point:    pubKey1.g2Point,
			PointBytes: pubKey1.PointBytes,
		}

		result := pubKey1Copy.Sub(pubKey1Copy2)
		if result == nil {
			t.Error("Expected non-nil result from Sub operation")
		}
	})
}

// TestSchemeAdapterMethods_ExtendedCoverage tests scheme adapter methods with better coverage
func TestSchemeAdapterMethods_ExtendedCoverage(t *testing.T) {
	scheme := NewScheme()

	t.Run("GenerateKeyPairFromSeed_ValidSeed", func(t *testing.T) {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(i)
		}

		privKey, pubKey, err := scheme.GenerateKeyPairFromSeed(seed)
		if err != nil {
			t.Fatalf("Expected no error for valid seed, but got: %v", err)
		}
		if privKey == nil {
			t.Error("Expected non-nil private key")
		}
		if pubKey == nil {
			t.Error("Expected non-nil public key")
		}
	})

	t.Run("NewPrivateKeyFromBytes_ValidData", func(t *testing.T) {
		data := make([]byte, 32)
		for i := range data {
			data[i] = byte(i)
		}

		privKey, err := scheme.NewPrivateKeyFromBytes(data)
		if err != nil {
			t.Fatalf("Expected no error for valid data, but got: %v", err)
		}
		if privKey == nil {
			t.Error("Expected non-nil private key")
		}
	})

	t.Run("NewPublicKeyFromBytes_ValidData", func(t *testing.T) {
		// Generate a valid public key first
		_, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		data := pubKey.Bytes()
		schemePubKey, err := scheme.NewPublicKeyFromBytes(data)
		if err != nil {
			t.Fatalf("Expected no error for valid data, but got: %v", err)
		}
		if schemePubKey == nil {
			t.Error("Expected non-nil public key")
		}
	})

	t.Run("NewPublicKeyFromHexString_ValidHex", func(t *testing.T) {
		// Generate a valid public key first
		_, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		hexStr := hex.EncodeToString(pubKey.Bytes())
		schemePubKey, err := scheme.NewPublicKeyFromHexString(hexStr)
		if err != nil {
			t.Fatalf("Expected no error for valid hex, but got: %v", err)
		}
		if schemePubKey == nil {
			t.Error("Expected non-nil public key")
		}
	})

	t.Run("NewSignatureFromBytes_ValidData", func(t *testing.T) {
		// Generate a valid signature first
		privKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		data := sig.Bytes()
		schemeSig, err := scheme.NewSignatureFromBytes(data)
		if err != nil {
			t.Fatalf("Expected no error for valid data, but got: %v", err)
		}
		if schemeSig == nil {
			t.Error("Expected non-nil signature")
		}
	})

	t.Run("PrivateKeyAdapter_Public", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		pubKey := privKey.Public()
		if pubKey == nil {
			t.Error("Expected non-nil public key")
		}
	})

	t.Run("PublicKeyAdapter_Bytes", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		bytes := pubKey.Bytes()
		if bytes == nil {
			t.Error("Expected non-nil bytes")
		}
	})

	t.Run("SignatureAdapter_Bytes", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		bytes := sig.Bytes()
		if bytes == nil {
			t.Error("Expected non-nil bytes")
		}
	})

	t.Run("SignatureAdapter_VerifyWithRawPublicKey", func(t *testing.T) {
		privKey, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Extract raw public key
		adapter := pubKey.(*publicKeyAdapter)
		rawPubKey := adapter.pk

		// Verify with raw public key
		valid, err := sig.Verify(rawPubKey, []byte("test"))
		if err != nil {
			t.Fatalf("Expected no error for verification, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid signature")
		}
	})

	t.Run("PrivateKeyAdapter_UnwrapPrivateKey", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		adapter := privKey.(*privateKeyAdapter)
		rawPrivKey := adapter.UnwrapPrivateKey()
		if rawPrivKey == nil {
			t.Error("Expected non-nil unwrapped private key")
		}
	})
}

// TestErrorPaths tests error handling paths that might not be covered
func TestErrorPaths(t *testing.T) {
	t.Run("hashToG1_ErrorHandling", func(t *testing.T) {
		// Test that hashToG1 properly handles errors (this tests the error case)
		// We can't easily trigger the error case, but we can test normal operation
		point, err := hashToG1([]byte("test message"))
		if err != nil {
			t.Errorf("Expected no error, but got: %v", err)
		}
		if point == nil {
			t.Error("Expected non-nil point")
		}
	})

	t.Run("SolidityHashToG1_EdgeCases", func(t *testing.T) {
		// Test various edge cases for SolidityHashToG1
		testCases := []struct {
			name string
			hash [32]byte
		}{
			{"AllZeros", [32]byte{}},
			{"AllOnes", func() [32]byte {
				var h [32]byte
				for i := range h {
					h[i] = 0xFF
				}
				return h
			}()},
			{"Pattern", func() [32]byte {
				var h [32]byte
				for i := range h {
					h[i] = byte(i * 7 % 256)
				}
				return h
			}()},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				point, err := SolidityHashToG1(tc.hash)
				if err != nil {
					t.Errorf("Expected no error for %s, but got: %v", tc.name, err)
				}
				if point == nil {
					t.Errorf("Expected non-nil point for %s", tc.name)
				}
			})
		}
	})
}

// TestSchemeAdapterMethods_DetailedCoverage tests scheme adapter methods with comprehensive coverage
func TestSchemeAdapterMethods_DetailedCoverage(t *testing.T) {
	scheme := NewScheme()

	t.Run("AggregateSignatures_InvalidSignatureType", func(t *testing.T) {
		// Create a fake signature that doesn't implement our interface properly
		fakeSignature := &fakeSignature{}

		_, err := scheme.AggregateSignatures([]signing.Signature{fakeSignature})
		if err == nil {
			t.Error("Expected error for invalid signature type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid signature type") {
			t.Errorf("Expected invalid signature type error, got: %v", err)
		}
	})

	t.Run("AggregateSignatures_NilSignatureInAdapter", func(t *testing.T) {
		// Create a signature adapter with nil signature
		nilSigAdapter := &signatureAdapter{sig: nil}

		_, err := scheme.AggregateSignatures([]signing.Signature{nilSigAdapter})
		if err == nil {
			t.Error("Expected error for nil signature in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil signature error, got: %v", err)
		}
	})

	t.Run("AggregateSignatures_ValidSignatures", func(t *testing.T) {
		// Generate valid signatures
		privKey1, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 1: %v", err)
		}
		privKey2, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 2: %v", err)
		}

		message := []byte("test message")
		sig1, err := privKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with key 1: %v", err)
		}
		sig2, err := privKey2.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with key 2: %v", err)
		}

		aggSig, err := scheme.AggregateSignatures([]signing.Signature{sig1, sig2})
		if err != nil {
			t.Fatalf("Expected no error for valid signatures, but got: %v", err)
		}
		if aggSig == nil {
			t.Error("Expected non-nil aggregated signature")
		}
	})

	t.Run("BatchVerify_InvalidPublicKeyType", func(t *testing.T) {
		// Create a fake public key that doesn't implement our interface properly
		fakePublicKey := &fakePublicKey{}
		fakeSignature := &fakeSignature{}

		_, err := scheme.BatchVerify([]signing.PublicKey{fakePublicKey}, []byte("test"), []signing.Signature{fakeSignature})
		if err == nil {
			t.Error("Expected error for invalid public key type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid public key type") {
			t.Errorf("Expected invalid public key type error, got: %v", err)
		}
	})

	t.Run("BatchVerify_NilPublicKeyInAdapter", func(t *testing.T) {
		// Create a public key adapter with nil public key
		nilPubKeyAdapter := &publicKeyAdapter{pk: nil}
		fakeSignature := &fakeSignature{}

		_, err := scheme.BatchVerify([]signing.PublicKey{nilPubKeyAdapter}, []byte("test"), []signing.Signature{fakeSignature})
		if err == nil {
			t.Error("Expected error for nil public key in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil public key error, got: %v", err)
		}
	})

	t.Run("BatchVerify_InvalidSignatureType", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create a fake signature that doesn't implement our interface properly
		fakeSignature := &fakeSignature{}

		_, err = scheme.BatchVerify([]signing.PublicKey{pubKey}, []byte("test"), []signing.Signature{fakeSignature})
		if err == nil {
			t.Error("Expected error for invalid signature type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid signature type") {
			t.Errorf("Expected invalid signature type error, got: %v", err)
		}
	})

	t.Run("BatchVerify_NilSignatureInAdapter", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create a signature adapter with nil signature
		nilSigAdapter := &signatureAdapter{sig: nil}

		_, err = scheme.BatchVerify([]signing.PublicKey{pubKey}, []byte("test"), []signing.Signature{nilSigAdapter})
		if err == nil {
			t.Error("Expected error for nil signature in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil signature error, got: %v", err)
		}
	})

	t.Run("BatchVerify_ValidBatch", func(t *testing.T) {
		// Generate valid key pairs and signatures
		privKey1, pubKey1, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 1: %v", err)
		}
		privKey2, pubKey2, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 2: %v", err)
		}

		message := []byte("test message")
		sig1, err := privKey1.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with key 1: %v", err)
		}
		sig2, err := privKey2.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign with key 2: %v", err)
		}

		valid, err := scheme.BatchVerify([]signing.PublicKey{pubKey1, pubKey2}, message, []signing.Signature{sig1, sig2})
		if err != nil {
			t.Fatalf("Expected no error for valid batch, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid batch verification")
		}
	})

	t.Run("AggregateVerify_InvalidPublicKeyType", func(t *testing.T) {
		// Create a fake public key that doesn't implement our interface properly
		fakePublicKey := &fakePublicKey{}
		fakeSignature := &fakeSignature{}

		_, err := scheme.AggregateVerify([]signing.PublicKey{fakePublicKey}, [][]byte{[]byte("test")}, fakeSignature)
		if err == nil {
			t.Error("Expected error for invalid public key type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid public key type") {
			t.Errorf("Expected invalid public key type error, got: %v", err)
		}
	})

	t.Run("AggregateVerify_NilPublicKeyInAdapter", func(t *testing.T) {
		// Create a public key adapter with nil public key
		nilPubKeyAdapter := &publicKeyAdapter{pk: nil}

		_, err := scheme.AggregateVerify([]signing.PublicKey{nilPubKeyAdapter}, [][]byte{[]byte("test")}, nil)
		if err == nil {
			t.Error("Expected error for nil public key in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil public key error, got: %v", err)
		}
	})

	t.Run("AggregateVerify_InvalidSignatureType", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create a fake signature that doesn't implement our interface properly
		fakeSignature := &fakeSignature{}

		_, err = scheme.AggregateVerify([]signing.PublicKey{pubKey}, [][]byte{[]byte("test")}, fakeSignature)
		if err == nil {
			t.Error("Expected error for invalid signature type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid signature type") {
			t.Errorf("Expected invalid signature type error, got: %v", err)
		}
	})

	t.Run("AggregateVerify_NilSignatureInAdapter", func(t *testing.T) {
		_, pubKey, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Create a signature adapter with nil signature
		nilSigAdapter := &signatureAdapter{sig: nil}

		_, err = scheme.AggregateVerify([]signing.PublicKey{pubKey}, [][]byte{[]byte("test")}, nilSigAdapter)
		if err == nil {
			t.Error("Expected error for nil signature in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil signature error, got: %v", err)
		}
	})

	t.Run("AggregateVerify_ValidAggregateVerification", func(t *testing.T) {
		// Generate valid key pairs and signatures
		privKey1, pubKey1, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 1: %v", err)
		}
		privKey2, pubKey2, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair 2: %v", err)
		}

		message1 := []byte("test message 1")
		message2 := []byte("test message 2")
		sig1, err := privKey1.Sign(message1)
		if err != nil {
			t.Fatalf("Failed to sign with key 1: %v", err)
		}
		sig2, err := privKey2.Sign(message2)
		if err != nil {
			t.Fatalf("Failed to sign with key 2: %v", err)
		}

		// Aggregate signatures
		aggSig, err := scheme.AggregateSignatures([]signing.Signature{sig1, sig2})
		if err != nil {
			t.Fatalf("Failed to aggregate signatures: %v", err)
		}

		valid, err := scheme.AggregateVerify([]signing.PublicKey{pubKey1, pubKey2}, [][]byte{message1, message2}, aggSig)
		if err != nil {
			t.Fatalf("Expected no error for valid aggregate verification, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid aggregate verification")
		}
	})

	t.Run("SignatureAdapter_VerifyWithInvalidPublicKeyType", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Create a fake public key that doesn't implement our interface properly
		fakePublicKey := &fakePublicKey{}

		_, err = sig.Verify(fakePublicKey, []byte("test"))
		if err == nil {
			t.Error("Expected error for invalid public key type, but got none")
		}
		if !strings.Contains(err.Error(), "invalid public key type") {
			t.Errorf("Expected invalid public key type error, got: %v", err)
		}
	})

	t.Run("SignatureAdapter_VerifyWithNilPublicKeyInAdapter", func(t *testing.T) {
		privKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		sig, err := privKey.Sign([]byte("test"))
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Create a public key adapter with nil public key
		nilPubKeyAdapter := &publicKeyAdapter{pk: nil}

		_, err = sig.Verify(nilPubKeyAdapter, []byte("test"))
		if err == nil {
			t.Error("Expected error for nil public key in adapter, but got none")
		}
		if !strings.Contains(err.Error(), "cannot be nil") {
			t.Errorf("Expected nil public key error, got: %v", err)
		}
	})
}

// Fake types for testing error conditions
type fakeSignature struct{}

func (f *fakeSignature) Verify(publicKey signing.PublicKey, message []byte) (bool, error) {
	return false, nil
}
func (f *fakeSignature) Bytes() []byte {
	return nil
}

type fakePublicKey struct{}

func (f *fakePublicKey) Bytes() []byte {
	return nil
}

// TestAdditionalErrorCases tests additional error cases for better coverage
func TestAdditionalErrorCases(t *testing.T) {
	t.Run("NewPublicKeyFromSolidity_ErrorCases", func(t *testing.T) {
		// Test error cases for NewPublicKeyFromSolidity that might not be covered
		g1Point := &SolidityBN254G1Point{
			X: big.NewInt(0),
			Y: big.NewInt(1), // This is not a valid point for G1
		}
		g2Point := &SolidityBN254G2Point{
			X: [2]*big.Int{big.NewInt(0), big.NewInt(0)},
			Y: [2]*big.Int{big.NewInt(1), big.NewInt(0)}, // This is not a valid point for G2
		}

		// This should fail for invalid points
		_, err := NewPublicKeyFromSolidity(g1Point, g2Point)
		if err == nil {
			t.Error("Expected error for invalid points, but got none")
		}
	})

	t.Run("BatchVerify_ErrorHandling", func(t *testing.T) {
		// Test error handling in BatchVerify
		privKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message")
		sig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Test with pairing error scenarios (though these are hard to trigger)
		valid, err := BatchVerify([]*PublicKey{pubKey}, message, []*Signature{sig})
		if err != nil {
			t.Errorf("Expected no error for valid batch verify, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid batch verification")
		}
	})

	t.Run("AggregateVerify_ErrorHandling", func(t *testing.T) {
		// Test error handling in AggregateVerify
		privKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message")
		sig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Test with pairing error scenarios (though these are hard to trigger)
		valid, err := AggregateVerify([]*PublicKey{pubKey}, [][]byte{message}, sig)
		if err != nil {
			t.Errorf("Expected no error for valid aggregate verify, but got: %v", err)
		}
		if !valid {
			t.Error("Expected valid aggregate verification")
		}
	})

	t.Run("Sign_ErrorHandling", func(t *testing.T) {
		// Test error handling in Sign method
		privKey, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test with various message types
		testMessages := [][]byte{
			nil,
			[]byte{},
			[]byte("test"),
			make([]byte, 1000), // Large message
		}

		for i, msg := range testMessages {
			_, err := privKey.Sign(msg)
			if err != nil {
				t.Errorf("Expected no error for message %d, but got: %v", i, err)
			}
		}
	})

	t.Run("Verify_ErrorHandling", func(t *testing.T) {
		// Test error handling in Verify method
		privKey, pubKey, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		message := []byte("test message")
		sig, err := privKey.Sign(message)
		if err != nil {
			t.Fatalf("Failed to sign: %v", err)
		}

		// Test with various message types
		testMessages := [][]byte{
			nil,
			[]byte{},
			[]byte("test"),
			make([]byte, 1000), // Large message
		}

		for i, msg := range testMessages {
			_, err := sig.Verify(pubKey, msg)
			if err != nil {
				t.Errorf("Expected no error for message %d, but got: %v", i, err)
			}
		}
	})
}
