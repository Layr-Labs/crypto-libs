# Crypto-libs

> **⚠️ ALPHA SOFTWARE - NOT AUDITED ⚠️**  
> **This library is in alpha development and has not undergone security auditing.**  
> **DO NOT USE IN PRODUCTION ENVIRONMENTS OR WITH REAL FUNDS.**  
> **Use at your own risk.**

A comprehensive Go library for BLS (Boneh-Lynn-Shacham) signatures supporting both BLS12-381 and BN254 elliptic curves. This library provides production-ready cryptographic primitives with EIP-2335 compliant keystores and unified interfaces for multi-curve operations.

## Features

- **Multi-curve BLS signatures**: Support for both BLS12-381 and BN254 curves
- **EIP-2335 compliant keystores**: Secure key storage with password-based encryption
- **Signature aggregation**: Efficient batch verification and signature combining
- **Hierarchical deterministic keys**: EIP-2333 support for BLS12-381
- **Ethereum compatibility**: BN254 precompile format support
- **Legacy keystore migration**: Automatic conversion from older formats
- **Unified API**: Common interface across different curve implementations

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

### Using the Unified Interface

```go
package main

import (
    "fmt"
    "github.com/Layr-Labs/crypto-libs/pkg/signing"
    "github.com/Layr-Labs/crypto-libs/pkg/bls381"
    "github.com/Layr-Labs/crypto-libs/pkg/bn254"
)

func signWithScheme(scheme signing.SigningScheme, message []byte) {
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
    
    fmt.Printf("Signature valid: %v\n", valid)
}

func main() {
    message := []byte("Hello, unified interface!")
    
    // Use BLS12-381
    signWithScheme(bls381.NewScheme(), message)
    
    // Use BN254
    signWithScheme(bn254.NewScheme(), message)
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

### Core Interfaces

#### `signing.SigningScheme`
The main interface for all curve implementations:
- `GenerateKeyPair()` - Create new random key pairs
- `GenerateKeyPairFromSeed(seed)` - Deterministic key generation
- `NewPrivateKeyFromBytes(data)` - Load private key from bytes
- `AggregateSignatures(sigs)` - Combine multiple signatures
- `BatchVerify(pks, msg, sigs)` - Efficient batch verification

#### `signing.PrivateKey`
- `Sign(message)` - Sign a message
- `Public()` - Get corresponding public key
- `Bytes()` - Serialize to bytes

#### `signing.Signature`
- `Verify(pubkey, message)` - Verify signature
- `Bytes()` - Serialize to bytes

### Curve-Specific Features

#### BLS12-381 (`pkg/bls381`)
- **EIP-2333 support**: `GenerateKeyPairEIP2333(seed, path)`
- **Standard compliance**: Full EIP-2333 hierarchical deterministic keys
- **Security**: Industry-standard BLS12-381 curve

#### BN254 (`pkg/bn254`)
- **Ethereum compatibility**: Precompile format support
- **Point operations**: Direct G1/G2 point manipulation
- **Solidity integration**: `NewPublicKeyFromSolidity(g1, g2)`

### Keystore Management

#### Creating Keystores
```go
keystore.SaveToKeystoreWithCurveType(privateKey, path, password, curveType, options)
```

#### Loading Keystores
```go
ks, err := keystore.LoadKeystoreFile(path)
privateKey, err := ks.GetPrivateKey(password, scheme)
```

#### Migration from Legacy
```go
newKs, err := keystore.ParseLegacyKeystoreToEIP2335Keystore(legacyJSON, password, scheme)
```

## Security Considerations

- **Password Security**: Use strong passwords for keystore encryption
- **Key Management**: Never expose private keys in logs or error messages
- **Randomness**: All key generation uses cryptographically secure random sources
- **Memory Safety**: Private keys are handled securely in memory
- **Standards Compliance**: Full EIP-2335 and EIP-2333 compliance

## Performance

- **Batch Operations**: Use `BatchVerify` for multiple signature verification
- **Signature Aggregation**: Combine signatures before verification when possible
- **Memory Usage**: Efficient elliptic curve point representation
- **Concurrency**: All operations are thread-safe

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
