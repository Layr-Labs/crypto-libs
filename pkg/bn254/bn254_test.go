package bn254

import (
	"bytes"
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

	t.Run("SignatureAdapter_NilAdapter", func(t *testing.T) {
		var nilAdapter *signatureAdapter = nil
		_, err := nilAdapter.Verify(nil, []byte("test"))
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
