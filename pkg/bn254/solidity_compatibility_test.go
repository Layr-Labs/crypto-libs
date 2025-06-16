package bn254

import (
	"crypto/sha256"
	"testing"
)

func TestSolidityCompatibility(t *testing.T) {
	t.Run("SolidityHashToG1", func(t *testing.T) {
		// Test with known hash values
		testHashes := [][32]byte{
			sha256.Sum256([]byte("test message 1")),
			sha256.Sum256([]byte("test message 2")),
			sha256.Sum256([]byte("")), // empty message
			{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
				0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}, // fixed hash
		}

		for i, hash := range testHashes {
			t.Run("Hash"+string(rune('0'+i)), func(t *testing.T) {
				point, err := SolidityHashToG1(hash)
				if err != nil {
					t.Fatalf("SolidityHashToG1 failed: %v", err)
				}

				// Check that the point is not nil
				if point == nil {
					t.Fatal("SolidityHashToG1 returned nil point")
				}

				// Check that the point is on the curve
				if !point.IsOnCurve() {
					t.Error("SolidityHashToG1 returned point not on curve")
				}

				// Check that the point is in the correct subgroup
				if !point.IsInSubGroup() {
					t.Error("SolidityHashToG1 returned point not in subgroup")
				}

				// Verify deterministic behavior - same hash should give same result
				point2, err := SolidityHashToG1(hash)
				if err != nil {
					t.Fatalf("Second SolidityHashToG1 call failed: %v", err)
				}
				if !point.Equal(point2) {
					t.Error("SolidityHashToG1 is not deterministic")
				}
			})
		}
	})

	t.Run("SoliditySignAndVerify", func(t *testing.T) {
		// Generate a key pair
		sk, pk, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair: %v", err)
		}

		// Test message hash
		messageHash := sha256.Sum256([]byte("test message for solidity compatibility"))

		// Sign with Solidity-compatible method
		sig, err := sk.SignSolidityCompatible(messageHash)
		if err != nil {
			t.Fatalf("Failed to sign with Solidity-compatible method: %v", err)
		}

		// Check that the signature is in G1
		if !sig.sig.IsOnCurve() {
			t.Error("Signature point is not on curve")
		}
		if !sig.sig.IsInSubGroup() {
			t.Error("Signature point is not in subgroup")
		}

		// Verify with Solidity-compatible method
		valid, err := sig.VerifySolidityCompatible(pk, messageHash)
		if err != nil {
			t.Fatalf("Failed to verify signature with Solidity-compatible method: %v", err)
		}
		if !valid {
			t.Error("Solidity-compatible signature verification failed")
		}

		// Verify that standard verification fails (due to different hash-to-curve methods)
		standardValid, err := sig.Verify(pk, messageHash[:])
		if err != nil {
			t.Fatalf("Failed to verify signature with standard method: %v", err)
		}
		if standardValid {
			t.Error("Standard verification should fail for Solidity-compatible signature")
		}
	})

	t.Run("SolidityCompatibilityConsistency", func(t *testing.T) {
		// Generate multiple key pairs and test consistency
		numKeys := 3
		messageHash := sha256.Sum256([]byte("consistency test message"))

		for i := 0; i < numKeys; i++ {
			sk, pk, err := GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair %d: %v", i, err)
			}

			// Sign and verify
			sig, err := sk.SignSolidityCompatible(messageHash)
			if err != nil {
				t.Fatalf("Failed to sign with key %d: %v", i, err)
			}

			valid, err := sig.VerifySolidityCompatible(pk, messageHash)
			if err != nil {
				t.Fatalf("Failed to verify signature for key %d: %v", i, err)
			}
			if !valid {
				t.Errorf("Signature verification failed for key %d", i)
			}

			// Test with wrong message hash
			wrongHash := sha256.Sum256([]byte("wrong message"))
			wrongValid, err := sig.VerifySolidityCompatible(pk, wrongHash)
			if err != nil {
				t.Fatalf("Failed to verify wrong signature for key %d: %v", i, err)
			}
			if wrongValid {
				t.Errorf("Signature verification should fail for wrong message hash with key %d", i)
			}
		}
	})

	t.Run("DifferentHashMethodsProduceDifferentResults", func(t *testing.T) {
		// Test that standard and Solidity hash methods produce different results
		message := []byte("test message")
		messageHash := sha256.Sum256(message)

		// Hash with standard method
		standardPoint, err := hashToG1(message)
		if err != nil {
			t.Fatalf("Failed to hash with standard method: %v", err)
		}

		// Hash with Solidity method
		solidityPoint, err := SolidityHashToG1(messageHash)
		if err != nil {
			t.Fatalf("Failed to hash with Solidity method: %v", err)
		}

		// They should be different (unless by extreme coincidence)
		if standardPoint.Equal(solidityPoint) {
			t.Error("Standard and Solidity hash methods produced the same result (this is extremely unlikely)")
		}
	})
}
