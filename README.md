# Crypto-libs

> **⚠️ ALPHA SOFTWARE - PENDING AUDIT ⚠️**  
> **This library is currently undergoing security auditing.**  
> **Exercise caution when using in production environments.**  
> **Use at your own risk.**

A comprehensive Go cryptographic library providing multiple signature schemes (BLS12-381, BN254, and secp256k1/ECDSA) with unified interfaces, secure key management, and Ethereum compatibility. This library implements production-ready cryptographic primitives with EIP-2335 compliant keystores and comprehensive security features.

## Project Overview

This library provides a comprehensive suite of cryptographic operations designed for blockchain and distributed systems applications. It supports three major signature schemes through a unified interface, enabling developers to switch between different cryptographic curves without changing application logic.

### Key Components

- **Multi-Signature Scheme Support**:
  - **BLS12-381**: Industry-standard BLS signatures with pairing-based cryptography
  - **BN254**: Ethereum-compatible BLS signatures optimized for EVM precompiles
  - **secp256k1/ECDSA**: Standard Ethereum transaction signatures

- **Unified Signing Interface** (`pkg/signing`):
  - Common API across all signature schemes
  - Pluggable architecture for curve implementations
  - Type-safe operations with comprehensive error handling

- **Advanced Cryptographic Features**:
  - **Signature Aggregation**: Combine multiple BLS signatures into one (BLS12-381 & BN254)
  - **Batch Verification**: Verify multiple signatures efficiently in a single operation
  - **Threshold Signatures**: Support for distributed key generation and signing
  - **Hierarchical Deterministic Keys**: EIP-2333 compliant HD key derivation for BLS12-381

- **Secure Key Management**:
  - **EIP-2335 Compliant Keystores**: Industry-standard encrypted key storage
  - **Multiple KDF Support**: Both scrypt and PBKDF2 key derivation functions
  - **Password Processing**: NFKD normalization and control code stripping per spec
  - **Legacy Migration**: Automatic conversion from V3/V4 keystore formats

- **Ethereum Integration**:
  - **Precompile Compatibility**: BN254 signatures work with Ethereum precompiles
  - **Solidity Interoperability**: Direct integration with smart contract verification
  - **Address Derivation**: Standard Ethereum address generation from ECDSA keys
  - **EIP-712 Support**: Structured data signing for ECDSA

## Installation

```bash
go get github.com/Layr-Labs/crypto-libs
```

## Quick Start

### Basic Usage with BLS12-381

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/bls381"
)

func main() {
    // Generate a new key pair
    privateKey, publicKey, err := bls381.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Sign a message
    message := []byte("Hello, BLS!")
    signature, err := privateKey.Sign(message)
    if err != nil {
        panic(err)
    }

    // Verify the signature
    valid, err := signature.Verify(publicKey, message)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Using ECDSA for Ethereum Compatibility

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
)

func main() {
    // Generate key pair
    privateKey, publicKey, err := ecdsa.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Derive Ethereum address
    address, err := privateKey.DeriveAddress()
    if err != nil {
        panic(err)
    }
    
    // Sign a message hash (32 bytes)
    messageHash := [32]byte{} // Your message hash here
    signature, err := privateKey.Sign(messageHash[:])
    if err != nil {
        panic(err)
    }

    // Verify with address
    valid, err := signature.VerifyWithAddress(messageHash[:], address)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Address: %s\n", address.Hex())
    fmt.Printf("Signature valid: %v\n", valid)
}
```

### Using the Unified Interface

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/signing"
    "github.com/Layr-Labs/crypto-libs/pkg/bls381"
    "github.com/Layr-Labs/crypto-libs/pkg/bn254"
    "github.com/Layr-Labs/crypto-libs/pkg/ecdsa"
)

func signWithScheme(scheme signing.SigningScheme, schemeName string, message []byte) {
    // Generate key pair using the scheme
    privateKey, publicKey, err := scheme.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Sign and verify
    signature, err := privateKey.Sign(message)
    if err != nil {
        panic(err)
    }

    valid, err := signature.Verify(publicKey, message)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("%s - Signature valid: %v\n", schemeName, valid)
}

func main() {
    message := []byte("Hello, unified interface!")
    
    // Use all three signature schemes through the same interface
    signWithScheme(bls381.NewScheme(), "BLS12-381", message)
    signWithScheme(bn254.NewScheme(), "BN254", message)
    signWithScheme(ecdsa.NewScheme(), "ECDSA", message)
}
```

### Working with Keystores

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/keystore"
    "github.com/Layr-Labs/crypto-libs/pkg/bls381"
)

func main() {
    // Generate a key pair
    scheme := bls381.NewScheme()
    privateKey, _, err := scheme.GenerateKeyPair()
    if err != nil {
        panic(err)
    }

    // Save to encrypted keystore
    password := "secure-password-123"
    err = keystore.SaveToKeystoreWithCurveType(
        privateKey, 
        "./my-keystore.json", 
        password, 
        "bls381", 
        keystore.Default(),
    )
    if err != nil {
        panic(err)
    }

    // Load from keystore
    ks, err := keystore.LoadKeystoreFile("./my-keystore.json")
    if err != nil {
        panic(err)
    }

    // Decrypt the private key
    loadedKey, err := ks.GetPrivateKey(password, scheme)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Successfully loaded private key: %x\n", loadedKey.Bytes()[:8])
}
```

### Signature Aggregation

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/bls381"
)

func main() {
    message := []byte("Aggregate this message")
    var signatures []*bls381.Signature
    var publicKeys []*bls381.PublicKey

    // Create multiple signatures
    for i := 0; i < 3; i++ {
        privateKey, publicKey, _ := bls381.GenerateKeyPair()
        signature, _ := privateKey.Sign(message)
        
        signatures = append(signatures, signature)
        publicKeys = append(publicKeys, publicKey)
    }

    // Aggregate signatures
    aggSig, err := bls381.AggregateSignatures(signatures)
    if err != nil {
        panic(err)
    }

    // Batch verify
    valid, err := bls381.BatchVerify(publicKeys, message, signatures)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Batch verification: %v\n", valid)
    fmt.Printf("Aggregated signature: %x\n", aggSig.Bytes()[:8])
}
```

## API Reference

### Architecture Details

#### Core Interfaces

##### `signing.SigningScheme`
The main interface providing a unified API across all signature schemes:
- `GenerateKeyPair()` - Create new random key pairs
- `GenerateKeyPairFromSeed(seed)` - Deterministic key generation
- `GenerateKeyPairEIP2333(seed, path)` - HD key derivation (BLS12-381 only)
- `NewPrivateKeyFromBytes(data)` - Load private key from bytes
- `NewPublicKeyFromBytes(data)` - Load public key from bytes
- `NewSignatureFromBytes(data)` - Load signature from bytes
- `AggregateSignatures(sigs)` - Combine multiple signatures (BLS only)
- `BatchVerify(pks, msg, sigs)` - Efficient batch verification
- `AggregateVerify(pks, msgs, aggSig)` - Verify aggregated signatures

##### `signing.PrivateKey`
- `Sign(message)` - Sign a message
- `Public()` - Get corresponding public key
- `Bytes()` - Serialize to bytes

##### `signing.Signature`
- `Verify(pubkey, message)` - Verify signature
- `Bytes()` - Serialize to bytes

### Implementation Details

#### BLS12-381 (`pkg/bls381`)
- **Curve**: BLS12-381 with 381-bit prime field
- **Security Level**: ~128 bits
- **Pairing**: Optimized ate pairing
- **Hash-to-Curve**: BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_
- **Key Features**:
  - EIP-2333 hierarchical deterministic key generation
  - Full signature aggregation support
  - Batch verification optimizations
  - Standards-compliant implementation

#### BN254 (`pkg/bn254`)
- **Curve**: Barreto-Naehrig curve with 254-bit prime field
- **Security Level**: ~100 bits (suitable for specific use cases)
- **Ethereum Precompiles**: Compatible with ecAdd, ecMul, ecPairing
- **Hash-to-Curve**: Multiple methods including Solidity-compatible try-and-increment
- **Key Features**:
  - Direct EVM precompile integration
  - Solidity contract verification support
  - G1/G2 point arithmetic operations
  - Public key aggregation for threshold schemes

#### secp256k1/ECDSA (`pkg/ecdsa`)
- **Curve**: secp256k1 (same as Bitcoin/Ethereum)
- **Security Level**: ~128 bits
- **Compatibility**: Full Ethereum transaction signing
- **Key Features**:
  - Deterministic key generation with PBKDF2
  - Ethereum address derivation
  - Recovery ID for public key recovery
  - Signature malleability protection

### Keystore System (`pkg/keystore`)

The keystore system provides secure, encrypted storage for private keys following the EIP-2335 standard with additional enhancements.

#### Features
- **EIP-2335 Compliance**: Full implementation of the Ethereum keystore standard
- **Multi-Curve Support**: Stores keys for BLS12-381, BN254, and ECDSA
- **KDF Options**: 
  - **scrypt**: Default, memory-hard function (N=262144, r=8, p=1)
  - **PBKDF2**: Alternative, iteration-based (iterations=262144)
- **Encryption**: AES-128-CTR with authenticated checksum
- **Password Processing**: NFKD normalization with control code stripping
- **Legacy Support**: Automatic migration from V3/V4 keystore formats

#### Security Features
- **Salt Validation**: 16-64 byte salts for KDF operations
- **Memory Limits**: Prevents excessive memory usage in scrypt
- **Parameter Validation**: Comprehensive checks on all cryptographic parameters
- **Secure Random Generation**: Uses crypto/rand for all random values

#### API Examples
```go
// Create keystore
keystore.SaveToKeystoreWithCurveType(privateKey, path, password, curveType, options)

// Load keystore
ks, err := keystore.LoadKeystoreFile(path)
privateKey, err := ks.GetPrivateKey(password, scheme)

// Migrate legacy keystore
newKs, err := keystore.ParseLegacyKeystoreToEIP2335Keystore(legacyJSON, password, scheme)
```

## Security Considerations

### Cryptographic Security
- **Constant-Time Operations**: Protection against timing attacks in ECDSA
- **Secure Random Generation**: All randomness from crypto/rand
- **Parameter Validation**: Comprehensive validation of all inputs
- **Malleability Protection**: ECDSA signatures use canonical S values
- **Subgroup Validation**: All curve points validated for correct subgroup membership

### Key Management Security
- **Memory Handling**: Sensitive data cleared from memory after use
- **Password Processing**: EIP-2335 compliant normalization
- **Encryption Standards**: AES-128-CTR with authenticated checksums
- **KDF Security**: Configurable iterations/memory parameters for resistance to brute force

### Implementation Security
- **Input Validation**: All inputs validated for type, length, and range
- **Error Handling**: Comprehensive error messages without leaking sensitive data
- **Standards Compliance**: Full compliance with EIP-2333, EIP-2335
- **Curve Security**: BLS12-381 (~128 bits), secp256k1 (~128 bits), BN254 (~100 bits)

## Performance Characteristics

### Optimization Strategies
- **Batch Verification**: Up to 50% faster than individual verification for BLS signatures
- **Signature Aggregation**: O(1) verification time regardless of signer count
- **Point Compression**: Reduced storage and transmission overhead
- **Jacobian Coordinates**: Optimized elliptic curve arithmetic

### Benchmarks (Approximate)
- **BLS12-381**:
  - Key Generation: ~2ms
  - Signing: ~3ms
  - Verification: ~5ms
  - Aggregation (10 sigs): ~1ms
  
- **BN254**:
  - Key Generation: ~1ms
  - Signing: ~2ms
  - Verification: ~3ms
  - Precompile Compatible: Yes

- **ECDSA/secp256k1**:
  - Key Generation: ~0.5ms
  - Signing: ~0.3ms
  - Verification: ~0.5ms
  - Ethereum Compatible: Yes

## Audit Considerations

This library is designed with security audit requirements in mind:

### Code Organization
- **Modular Design**: Clear separation between signature schemes
- **Interface Segregation**: Well-defined boundaries between components
- **Minimal Dependencies**: Uses established libraries (gnark-crypto, go-ethereum)

### Security Practices
- **Input Validation**: Every function validates inputs before processing
- **Error Propagation**: Clear error messages without information leakage
- **Memory Management**: Explicit clearing of sensitive data
- **Test Coverage**: Comprehensive unit and integration tests

### Areas of Focus for Auditors
1. **Cryptographic Operations**: Verify correctness of signature algorithms
2. **Key Derivation**: Check EIP-2333/2335 compliance
3. **Random Number Generation**: Ensure proper entropy sources
4. **Side-Channel Resistance**: Review timing attack mitigations
5. **Input Validation**: Check for integer overflows and boundary conditions

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Run linting (`make lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Development Commands

```bash
# Install dependencies
make deps

# Run tests
make test

# Run linting
make lint

# Format code
make fmt

# Check formatting
make fmtcheck
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on [gnark-crypto](https://github.com/consensys/gnark-crypto) for elliptic curve operations
- Implements [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335) keystore standard
- Supports [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333) hierarchical deterministic keys
