package keystore

import (
	"crypto/aes"
	cryptoCipher "crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Layr-Labs/crypto-libs/pkg/signing"

	"github.com/Layr-Labs/crypto-libs/pkg/keystore/legacy"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/unicode/norm"

	"github.com/Layr-Labs/crypto-libs/pkg/bls381"
	"github.com/Layr-Labs/crypto-libs/pkg/bn254"
	"github.com/google/uuid"
)

// Package keystore implements an EIP-2335 compliant keystore for BLS private keys.
// It provides support for both BLS12-381 and BN254 curve types with the following features:
//
// 1. EIP-2335 compliance for standardized keystore format
// 2. Backward compatibility with legacy keystore format
// 3. Multiple KDF support (scrypt and pbkdf2)
// 4. AES-128-CTR encryption
// 5. Password processing according to EIP-2335 spec (NFKD normalization, control code stripping)
//
// The keystore format follows the EIP-2335 specification with crypto modules for KDF, checksum,
// and cipher operations while adding a custom "curveType" field to support both BLS12-381 and
// BN254 curve types.

// ErrInvalidKeystoreFile is returned when a keystore file is not valid or is corrupted
var ErrInvalidKeystoreFile = errors.New("invalid keystore file")

// Module represents a cryptographic module in EIP-2335
type Module struct {
	Function string                 `json:"function"`
	Params   map[string]interface{} `json:"params"`
	Message  string                 `json:"message"`
}

// EIP2335Keystore represents a BLS private key encrypted using EIP-2335 format
type EIP2335Keystore struct {
	Crypto struct {
		KDF      Module `json:"kdf"`
		Checksum Module `json:"checksum"`
		Cipher   Module `json:"cipher"`
	} `json:"crypto"`
	Description string `json:"description,omitempty"`
	Pubkey      string `json:"pubkey"`
	Path        string `json:"path"`
	UUID        string `json:"uuid"`
	Version     int    `json:"version"`
	CurveType   string `json:"curveType,omitempty"` // Custom field, either "bls381" or "bn254"
}

// LegacyKeystore represents the old keystore format
// type LegacyKeystore struct {
// 	PublicKey string              `json:"publicKey"`
// 	Crypto    keystore.CryptoJSON `json:"crypto"`
// 	UUID      string              `json:"uuid"`
// 	Version   int                 `json:"version"`
// 	CurveType string              `json:"curveType"`
// }

// processPassword prepares a password according to EIP-2335:
// 1. Convert to NFKD representation
// 2. Strip control codes (C0, C1, and Delete)
// 3. UTF-8 encode (handled by Go strings)
func processPassword(password string) []byte {
	// Step 1: Convert to NFKD representation
	normalized := norm.NFKD.String(password)

	// Step 2: Strip control codes
	var cleaned []rune
	for _, r := range normalized {
		// Skip C0 (0x00-0x1F), C1 (0x80-0x9F), and Delete (0x7F)
		if (r >= 0x00 && r <= 0x1F) || (r >= 0x80 && r <= 0x9F) || r == 0x7F {
			continue
		}
		cleaned = append(cleaned, r)
	}

	// Return the UTF-8 encoded string
	return []byte(string(cleaned))
}

// validateSalt extracts and validates salt parameter according to EIP-2335
func validateSalt(params map[string]interface{}) ([]byte, error) {
	saltParam, ok := params["salt"]
	if !ok {
		return nil, fmt.Errorf("missing salt parameter")
	}
	saltStr, ok := saltParam.(string)
	if !ok {
		return nil, fmt.Errorf("salt parameter must be a string")
	}
	if saltStr == "" {
		return nil, fmt.Errorf("salt cannot be empty")
	}

	salt, err := hex.DecodeString(saltStr)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}

	// EIP-2335 salt validation
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt too short: must be at least 16 bytes, got %d", len(salt))
	}
	if len(salt) > 64 {
		return nil, fmt.Errorf("salt too long: must be at most 64 bytes, got %d", len(salt))
	}

	return salt, nil
}

// validateDklen extracts and validates dklen parameter according to EIP-2335
func validateDklen(params map[string]interface{}) (int, error) {
	dklenParam, ok := params["dklen"]
	if !ok {
		return 0, fmt.Errorf("missing dklen parameter")
	}
	dklen, ok := dklenParam.(float64)
	if !ok {
		return 0, fmt.Errorf("dklen must be a number")
	}

	// EIP-2335 requires exactly 32 bytes for derived key length
	if int(dklen) != 32 {
		return 0, fmt.Errorf("invalid dklen: EIP-2335 requires 32 bytes, got %d", int(dklen))
	}

	return int(dklen), nil
}

// deriveKeyFromPassword derives a key from the password using the specified KDF
func deriveKeyFromPassword(password string, kdf Module) ([]byte, error) {
	if kdf.Function == "" {
		return nil, fmt.Errorf("KDF function cannot be empty")
	}
	if kdf.Params == nil {
		return nil, fmt.Errorf("KDF parameters cannot be nil")
	}

	processedPassword := processPassword(password)

	switch kdf.Function {
	case "pbkdf2":
		// Extract and validate common parameters
		salt, err := validateSalt(kdf.Params)
		if err != nil {
			return nil, err
		}

		dklen, err := validateDklen(kdf.Params)
		if err != nil {
			return nil, err
		}

		// Extract PBKDF2-specific parameters
		cParam, ok := kdf.Params["c"]
		if !ok {
			return nil, fmt.Errorf("missing iterations count parameter")
		}
		c, ok := cParam.(float64)
		if !ok {
			return nil, fmt.Errorf("iterations count must be a number")
		}

		prfParam, ok := kdf.Params["prf"]
		if !ok {
			return nil, fmt.Errorf("missing prf parameter")
		}
		prf, ok := prfParam.(string)
		if !ok || prf != "hmac-sha256" {
			return nil, fmt.Errorf("unsupported PRF: %v", prf)
		}

		// PBKDF2-specific validation - EIP-2335 reference value is 262144
		if int(c) < 1000 {
			return nil, fmt.Errorf("iteration count too low: must be at least 1000, got %d", int(c))
		}
		if int(c) > 10000000 {
			return nil, fmt.Errorf("iteration count too high: must be at most 10000000, got %d", int(c))
		}

		return pbkdf2.Key(processedPassword, salt, int(c), dklen, sha256.New), nil

	case "scrypt":
		// Extract and validate common parameters
		salt, err := validateSalt(kdf.Params)
		if err != nil {
			return nil, err
		}

		dklen, err := validateDklen(kdf.Params)
		if err != nil {
			return nil, err
		}

		// Extract scrypt-specific parameters
		nParam, ok := kdf.Params["n"]
		if !ok {
			return nil, fmt.Errorf("missing N parameter")
		}
		n, ok := nParam.(float64)
		if !ok {
			return nil, fmt.Errorf("N parameter must be a number")
		}

		rParam, ok := kdf.Params["r"]
		if !ok {
			return nil, fmt.Errorf("missing r parameter")
		}
		r, ok := rParam.(float64)
		if !ok {
			return nil, fmt.Errorf("r parameter must be a number")
		}

		pParam, ok := kdf.Params["p"]
		if !ok {
			return nil, fmt.Errorf("missing p parameter")
		}
		p, ok := pParam.(float64)
		if !ok {
			return nil, fmt.Errorf("p parameter must be a number")
		}

		// Scrypt-specific validation
		// N parameter validation - must be a power of 2
		nInt := int(n)
		if nInt < 1024 {
			return nil, fmt.Errorf("N parameter too low: must be at least 1024, got %d", nInt)
		}
		if nInt > 1048576 { // 2^20, reasonable upper bound
			return nil, fmt.Errorf("N parameter too high: must be at most 1048576, got %d", nInt)
		}
		if nInt&(nInt-1) != 0 {
			return nil, fmt.Errorf("N parameter must be a power of 2, got %d", nInt)
		}

		// r parameter validation - EIP-2335 reference value is 8
		rInt := int(r)
		if rInt < 1 {
			return nil, fmt.Errorf("r parameter too low: must be at least 1, got %d", rInt)
		}
		if rInt > 32 {
			return nil, fmt.Errorf("r parameter too high: must be at most 32, got %d", rInt)
		}

		// p parameter validation - EIP-2335 reference value is 1
		pInt := int(p)
		if pInt < 1 {
			return nil, fmt.Errorf("p parameter too low: must be at least 1, got %d", pInt)
		}
		if pInt > 16 {
			return nil, fmt.Errorf("p parameter too high: must be at most 16, got %d", pInt)
		}

		// Memory usage validation - prevent excessive memory consumption
		// Memory usage is approximately 128 * N * r bytes
		memoryUsage := 128 * nInt * rInt
		if memoryUsage > 1024*1024*1024 { // 1GB limit
			return nil, fmt.Errorf("scrypt parameters would require too much memory: %d bytes (max 1GB)", memoryUsage)
		}

		return scrypt.Key(processedPassword, salt, nInt, rInt, pInt, dklen)

	default:
		return nil, fmt.Errorf("unsupported KDF function: %s", kdf.Function)
	}
}

// verifyPassword checks if the provided password is correct
func verifyPassword(decryptionKey []byte, checksum Module, cipherMessage string) (bool, error) {
	// Input validation
	if len(decryptionKey) == 0 {
		return false, fmt.Errorf("decryption key cannot be nil")
	}

	if checksum.Function == "" {
		return false, fmt.Errorf("checksum function cannot be empty")
	}
	if cipherMessage == "" {
		return false, fmt.Errorf("cipher message cannot be empty")
	}

	if checksum.Function != "sha256" {
		return false, fmt.Errorf("unsupported checksum function: %s", checksum.Function)
	}

	if checksum.Message == "" {
		return false, fmt.Errorf("checksum message cannot be empty")
	}

	// Get the second 16 bytes of the decryption key
	dkSlice := decryptionKey[16:32]

	// Decode the cipher message
	cipherBytes, err := hex.DecodeString(cipherMessage)
	if err != nil {
		return false, fmt.Errorf("invalid cipher message: %w", err)
	}

	// Create the pre-image: DK_slice | cipher_message
	preImage := append(dkSlice, cipherBytes...)

	// Calculate the checksum
	calculatedChecksum := sha256.Sum256(preImage)
	checksumHex := hex.EncodeToString(calculatedChecksum[:])

	// Compare with the stored checksum
	return checksumHex == checksum.Message, nil
}

// decryptSecret decrypts the encrypted private key
func decryptSecret(decryptionKey []byte, cipher Module) ([]byte, error) {
	if len(decryptionKey) == 0 {
		return nil, fmt.Errorf("decryption key cannot be nil or 0 bytes")
	}

	if cipher.Function == "" {
		return nil, fmt.Errorf("cipher function cannot be empty")
	}
	if cipher.Params == nil {
		return nil, fmt.Errorf("cipher parameters cannot be nil")
	}
	if cipher.Message == "" {
		return nil, fmt.Errorf("cipher message cannot be empty")
	}

	if cipher.Function != "aes-128-ctr" {
		return nil, fmt.Errorf("unsupported cipher function: %s", cipher.Function)
	}

	// Validate and decode the IV
	ivParam, ok := cipher.Params["iv"]
	if !ok {
		return nil, fmt.Errorf("missing IV parameter")
	}
	ivStr, ok := ivParam.(string)
	if !ok {
		return nil, fmt.Errorf("IV parameter must be a string")
	}
	if ivStr == "" {
		return nil, fmt.Errorf("IV cannot be empty")
	}

	iv, err := hex.DecodeString(ivStr)
	if err != nil {
		return nil, fmt.Errorf("invalid IV: %w", err)
	}

	// Validate IV length for AES-128-CTR
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV length: expected 16 bytes, got %d", len(iv))
	}

	cipherText, err := hex.DecodeString(cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("invalid cipher text: %w", err)
	}

	// Validate cipher text length
	if len(cipherText) == 0 {
		return nil, fmt.Errorf("cipher text cannot be empty")
	}

	// Use only the first 16 bytes of the decryption key for AES-128
	key := decryptionKey[:16]

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Create the CTR mode
	ctr := cryptoCipher.NewCTR(block, iv)

	// Decrypt the cipher text
	plainText := make([]byte, len(cipherText))
	ctr.XORKeyStream(plainText, cipherText)

	return plainText, nil
}

// GetPrivateKey decrypts and returns the private key from the keystore
func (k *EIP2335Keystore) GetPrivateKey(password string, scheme signing.SigningScheme) (signing.PrivateKey, error) {

	if k == nil {
		return nil, fmt.Errorf("keystore data cannot be nil")
	}

	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Validate keystore structure
	if k.Crypto.KDF.Function == "" {
		return nil, fmt.Errorf("keystore KDF function cannot be empty")
	}
	if k.Crypto.Checksum.Function == "" {
		return nil, fmt.Errorf("keystore checksum function cannot be empty")
	}
	if k.Crypto.Cipher.Function == "" {
		return nil, fmt.Errorf("keystore cipher function cannot be empty")
	}

	// Derive decryption key from password
	decryptionKey, err := deriveKeyFromPassword(password, k.Crypto.KDF)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Verify password
	valid, err := verifyPassword(decryptionKey, k.Crypto.Checksum, k.Crypto.Cipher.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("invalid password")
	}

	// Decrypt the private key
	keyBytes, err := decryptSecret(decryptionKey, k.Crypto.Cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Validate decrypted key bytes
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("decrypted private key is empty")
	}

	// If scheme is nil, try to determine the scheme from the curve type in the keystore
	if scheme == nil && k.CurveType != "" {
		scheme, err = GetSigningSchemeForCurveType(k.CurveType)
		if err != nil {
			return nil, fmt.Errorf("failed to determine signing scheme: %w", err)
		}
	}

	// If scheme is still nil, we can't proceed
	if scheme == nil {
		return nil, fmt.Errorf("no signing scheme provided and unable to determine from keystore")
	}

	// Recreate the private key using the provided scheme
	privateKey, err := scheme.NewPrivateKeyFromBytes(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key from decrypted data: %w", err)
	}

	return privateKey, nil
}

// GetBN254PrivateKey gets a BN254 private key from the keystore
func (k *EIP2335Keystore) GetBN254PrivateKey(password string) (*bn254.PrivateKey, error) {
	if k == nil {
		return nil, fmt.Errorf("keystore data cannot be nil")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	scheme, err := GetSigningSchemeForCurveType("bn254")
	if err != nil {
		return nil, err
	}

	privKey, err := k.GetPrivateKey(password, scheme)
	if err != nil {
		return nil, err
	}

	if privKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Try to use the UnwrapPrivateKey method if available
	type unwrapper interface {
		UnwrapPrivateKey() *bn254.PrivateKey
	}

	if unwrapper, ok := privKey.(unwrapper); ok {
		unwrapped := unwrapper.UnwrapPrivateKey()
		if unwrapped == nil {
			return nil, fmt.Errorf("unwrapped private key is nil")
		}
		return unwrapped, nil
	}

	// Fall back to recreating from bytes if unwrapper not available
	rawBytes := privKey.Bytes()
	if len(rawBytes) > 0 {
		bn254PrivKey, err := bn254.NewPrivateKeyFromBytes(rawBytes)
		if err == nil {
			return bn254PrivKey, nil
		}
		return nil, fmt.Errorf("failed to create BN254 private key from bytes: %w", err)
	}

	return nil, fmt.Errorf("private key is not of compatible bn254 type or cannot be converted")
}

// GetBLS381PrivateKey gets a BLS381 private key from the keystore
func (k *EIP2335Keystore) GetBLS381PrivateKey(password string) (*bls381.PrivateKey, error) {
	if k == nil {
		return nil, fmt.Errorf("keystore data cannot be nil")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	scheme, err := GetSigningSchemeForCurveType("bls381")
	if err != nil {
		return nil, err
	}

	privKey, err := k.GetPrivateKey(password, scheme)
	if err != nil {
		return nil, err
	}

	if privKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}

	// Try to use an unwrapper method if available
	type unwrapper interface {
		UnwrapPrivateKey() *bls381.PrivateKey
	}

	if unwrapper, ok := privKey.(unwrapper); ok {
		unwrapped := unwrapper.UnwrapPrivateKey()
		if unwrapped == nil {
			return nil, fmt.Errorf("unwrapped private key is nil")
		}
		return unwrapped, nil
	}

	// Fall back to recreating from bytes if unwrapper not available
	rawBytes := privKey.Bytes()
	if len(rawBytes) > 0 {
		bls381PrivKey, err := bls381.NewPrivateKeyFromBytes(rawBytes)
		if err == nil {
			return bls381PrivKey, nil
		}
		return nil, fmt.Errorf("failed to create BLS381 private key from bytes: %w", err)
	}

	return nil, fmt.Errorf("private key is not of compatible bls381 type or cannot be converted")
}

// Options provides configuration options for keystore operations
type Options struct {
	// ScryptN is the N parameter of scrypt encryption algorithm
	ScryptN int
	// ScryptP is the P parameter of scrypt encryption algorithm
	ScryptP int
	// ScryptR is the R parameter of scrypt encryption algorithm (added for EIP-2335)
	ScryptR int
	// KDFType selects which KDF to use ("scrypt" or "pbkdf2")
	KDFType string
	// Description is an optional description for the keystore
	Description string
}

// Default returns the default options for keystore operations
func Default() *Options {
	return &Options{
		ScryptN:     262144, // EIP-2335 reference value
		ScryptP:     1,      // EIP-2335 reference value
		ScryptR:     8,      // EIP-2335 reference value
		KDFType:     "scrypt",
		Description: "",
	}
}

func ParseLegacyKeystoreToEIP2335Keystore(legacyJSON string, password string, scheme signing.SigningScheme) (*EIP2335Keystore, error) {
	if strings.TrimSpace(legacyJSON) == "" {
		return nil, fmt.Errorf("legacy keystore JSON cannot be empty")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if scheme == nil {
		return nil, fmt.Errorf("signing scheme cannot be nil")
	}

	lks, err := legacy.ParseKeystoreJSON(legacyJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse legacy keystore: %w", err)
	}

	if lks == nil {
		return nil, fmt.Errorf("parsed legacy keystore is nil")
	}

	pk, err := lks.GetPrivateKey(password, scheme)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key from legacy keystore: %w", err)
	}

	if pk == nil {
		return nil, fmt.Errorf("private key from legacy keystore is nil")
	}

	// Convert legacy format to EIP-2335 format
	return GenerateKeystore(pk, password, lks.CurveType, Default())
}

// ParseKeystoreJSON takes a string representation of the keystore JSON and returns the EIP2335Keystore struct
func ParseKeystoreJSON(keystoreJSON string) (*EIP2335Keystore, error) {

	if keystoreJSON == "" {
		return nil, ErrInvalidKeystoreFile
	}

	// Check for empty or whitespace-only input
	trimmed := strings.TrimSpace(keystoreJSON)
	if trimmed == "" || trimmed == "{}" {
		return nil, ErrInvalidKeystoreFile
	}

	// Validate JSON length (reasonable limit to prevent DoS)
	if len(keystoreJSON) > 2*1024*1024 { // 2MB limit
		return nil, fmt.Errorf("keystore JSON too large (max 2MB)")
	}

	var ks EIP2335Keystore
	if err := json.Unmarshal([]byte(keystoreJSON), &ks); err != nil {
		return nil, fmt.Errorf("failed to parse keystore JSON: %w", err)
	}

	// Verify it's a valid keystore by checking required fields
	// An EIP-2335 compliant keystore must have either:
	// 1. A valid pubkey field (non-empty)
	// 2. A valid crypto object with proper KDF function
	if ks.Pubkey == "" || ks.Crypto.KDF.Function == "" {
		return nil, ErrInvalidKeystoreFile
	}

	// Additional validation for critical fields
	if ks.Crypto.Checksum.Function == "" {
		return nil, ErrInvalidKeystoreFile
	}
	if ks.Crypto.Cipher.Function == "" {
		return nil, ErrInvalidKeystoreFile
	}

	return &ks, nil
}

// DetermineCurveType attempts to determine the curve type based on the private key
// This is a best-effort function that uses the curveStr path in the keygen operation
func DetermineCurveType(curveStr string) string {
	if curveStr == "" {
		return ""
	}

	switch strings.ToLower(strings.TrimSpace(curveStr)) {
	case "bls381":
		return "bls381"
	case "bn254":
		return "bn254"
	default:
		// Default to empty if we can't determine
		return ""
	}
}

// generateRandomIV generates a random IV for AES encryption
func generateRandomIV() ([]byte, error) {
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate random IV: %w", err)
	}
	return iv, nil
}

// generateRandomSalt generates a random salt for KDF
func generateRandomSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}

func GenerateKeystore(privateKey signing.PrivateKey, password, curveType string, opts *Options) (*EIP2335Keystore, error) {

	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	determinedCurveType := DetermineCurveType(curveType)
	if determinedCurveType == "" {
		return nil, fmt.Errorf("curve type cannot be empty")
	}

	if opts == nil {
		opts = Default()
	}

	// Validate options
	if opts.KDFType != "" && opts.KDFType != "scrypt" && opts.KDFType != "pbkdf2" {
		return nil, fmt.Errorf("invalid KDF type: %s (must be 'scrypt' or 'pbkdf2')", opts.KDFType)
	}

	// Generate UUID
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	// Get the public key
	publicKey := privateKey.Public()
	pubkeyBytes := publicKey.Bytes()
	pubkeyHex := hex.EncodeToString(pubkeyBytes)

	// Generate salt and IV
	salt, err := generateRandomSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	iv, err := generateRandomIV()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Process password
	processedPassword := processPassword(password)

	// Set up KDF parameters
	var decryptionKey []byte
	var kdfModule Module

	if opts.KDFType == "pbkdf2" {
		// PBKDF2 parameters
		kdfModule = Module{
			Function: "pbkdf2",
			Params: map[string]interface{}{
				"dklen": float64(32),
				"c":     float64(262144), // Iterations
				"prf":   "hmac-sha256",
				"salt":  hex.EncodeToString(salt),
			},
			Message: "",
		}
		decryptionKey = pbkdf2.Key(processedPassword, salt, 262144, 32, sha256.New)
	} else {
		// Default to scrypt - validate parameters
		if opts.ScryptN <= 0 || opts.ScryptR <= 0 || opts.ScryptP <= 0 {
			return nil, fmt.Errorf("invalid scrypt parameters: N=%d, R=%d, P=%d", opts.ScryptN, opts.ScryptR, opts.ScryptP)
		}

		kdfModule = Module{
			Function: "scrypt",
			Params: map[string]interface{}{
				"dklen": float64(32),
				"n":     float64(opts.ScryptN),
				"r":     float64(opts.ScryptR),
				"p":     float64(opts.ScryptP),
				"salt":  hex.EncodeToString(salt),
			},
			Message: "",
		}
		decryptionKey, err = scrypt.Key(processedPassword, salt, opts.ScryptN, opts.ScryptR, opts.ScryptP, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key: %w", err)
		}
	}

	// Validate decryption key
	if len(decryptionKey) != 32 {
		return nil, fmt.Errorf("derived key has invalid length: expected 32 bytes, got %d", len(decryptionKey))
	}

	// Encrypt the private key
	// Use only the first 16 bytes of the decryption key for AES-128
	key := decryptionKey[:16]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Encrypt the private key
	privateKeyBytes := privateKey.Bytes()
	cipherText := make([]byte, len(privateKeyBytes))
	ctrCipher := cryptoCipher.NewCTR(block, iv)
	ctrCipher.XORKeyStream(cipherText, privateKeyBytes)

	// Set up cipher module
	cipherModule := Module{
		Function: "aes-128-ctr",
		Params: map[string]interface{}{
			"iv": hex.EncodeToString(iv),
		},
		Message: hex.EncodeToString(cipherText),
	}

	// Create checksum
	// Get the second 16 bytes of the decryption key
	dkSlice := decryptionKey[16:32]
	preImage := append(dkSlice, cipherText...)
	checksum := sha256.Sum256(preImage)

	// Set up checksum module
	checksumModule := Module{
		Function: "sha256",
		Params:   map[string]interface{}{},
		Message:  hex.EncodeToString(checksum[:]),
	}

	// Create path based on curve type
	var path string
	if curveType == "bls381" {
		path = "m/12381/60/0/0" // Standard path for BLS12-381
	} else {
		path = "m/1/0/0" // Simple path for BN254 (non-standard)
	}

	// Create the ks structure
	ks := &EIP2335Keystore{
		Pubkey:      pubkeyHex,
		UUID:        id.String(),
		Version:     4,
		CurveType:   curveType,
		Path:        path,
		Description: opts.Description,
	}
	ks.Crypto.KDF = kdfModule
	ks.Crypto.Checksum = checksumModule
	ks.Crypto.Cipher = cipherModule

	return ks, nil
}

// SaveToKeystoreWithCurveType saves a private key to a keystore file using the EIP-2335 format
// and includes the curve type in the keystore file
func SaveToKeystoreWithCurveType(privateKey signing.PrivateKey, filePath, password, curveType string, opts *Options) error {

	if privateKey == nil {
		return fmt.Errorf("private key cannot be nil")
	}
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	determinedCurveType := DetermineCurveType(curveType)
	if determinedCurveType == "" {
		return fmt.Errorf("curve type cannot be empty")
	}

	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)
	if cleanPath != filePath {
		return fmt.Errorf("invalid file path")
	}

	ks, err := GenerateKeystore(privateKey, password, curveType, opts)
	if err != nil {
		return fmt.Errorf("failed to generate keystore: %w", err)
	}

	// Create the directory if it doesn't exist
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to JSON
	content, err := json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keystore: %w", err)
	}

	// Write to file
	if err := os.WriteFile(cleanPath, content, 0600); err != nil {
		return fmt.Errorf("failed to write keystore file: %w", err)
	}

	return nil
}

// GetSigningSchemeForCurveType returns the appropriate signing scheme based on curve type
func GetSigningSchemeForCurveType(curveType string) (signing.SigningScheme, error) {

	switch strings.ToLower(strings.TrimSpace(curveType)) {
	case "bls381":
		return bls381.NewScheme(), nil
	case "bn254":
		return bn254.NewScheme(), nil
	default:
		return nil, fmt.Errorf("unsupported curve type: %s", curveType)
	}
}

// LoadKeystoreFile loads a keystore from a file and returns the parsed EIP2335Keystore struct
func LoadKeystoreFile(filePath string) (*EIP2335Keystore, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Clean the file path to prevent directory traversal
	cleanPath := filepath.Clean(filePath)

	// Check if file exists and is readable
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to access keystore file: %w", err)
	}

	// Validate file size (reasonable limit to prevent DoS)
	if fileInfo.Size() > 2*1024*1024 { // 10MB limit
		return nil, fmt.Errorf("keystore file too large (max 10MB)")
	}

	// Read keystore file
	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keystore file: %w", err)
	}

	// Parse and return the keystore
	return ParseKeystoreJSON(string(content))
}

// TestKeystore tests a keystore by signing a test message
func TestKeystore(filePath, password string, scheme signing.SigningScheme) error {
	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}
	if scheme == nil {
		return fmt.Errorf("signing scheme cannot be nil")
	}

	// Load the keystore file
	keystoreData, err := LoadKeystoreFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to load keystore file: %w", err)
	}

	if keystoreData == nil {
		return fmt.Errorf("loaded keystore data is nil")
	}

	// Load the private key from keystore
	privateKey, err := keystoreData.GetPrivateKey(password, scheme)
	if err != nil {
		return fmt.Errorf("failed to load private key from keystore: %w", err)
	}

	if privateKey == nil {
		return fmt.Errorf("private key is nil")
	}

	// Get the public key
	publicKey := privateKey.Public()
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}

	// Test signing a message
	testMessage := []byte("Test message for keystore verification")
	sig, err := privateKey.Sign(testMessage)
	if err != nil {
		return fmt.Errorf("failed to sign test message: %w", err)
	}

	if sig == nil {
		return fmt.Errorf("signature is nil")
	}

	// Verify signature
	valid, err := sig.Verify(publicKey, testMessage)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	if !valid {
		return fmt.Errorf("keystore verification failed: signature is invalid")
	}

	return nil
}

// GenerateRandomPassword generates a cryptographically secure random password
func GenerateRandomPassword(length int) (string, error) {
	if length < 16 {
		length = 16 // Minimum password length for security
	}
	if length > 128 {
		return "", fmt.Errorf("password length too long (max 128 characters)")
	}

	// Create a byte slice to hold the random password
	bytes := make([]byte, length)

	// Fill with random bytes
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Define character set (alphanumeric + special chars)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetLen := len(charset)

	// Convert random bytes to character set
	for i := 0; i < length; i++ {
		bytes[i] = charset[int(bytes[i])%charsetLen]
	}

	return string(bytes), nil
}
