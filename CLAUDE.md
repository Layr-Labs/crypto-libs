# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go library for cryptographic operations implementing BLS signatures for both BLS12-381 and BN254 elliptic curves. The library provides:

- BLS signature schemes for BLS12-381 and BN254 curves
- EIP-2335 compliant keystores with backward compatibility  
- Unified signing interface for multiple curve types
- Legacy keystore migration capabilities

## Core Architecture

### Curve Implementations
- `pkg/bls381/` - BLS12-381 implementation with EIP-2333 support for hierarchical deterministic keys
- `pkg/bn254/` - BN254 implementation with Ethereum precompile compatibility

### Unified Interface
- `pkg/signing/` - Generic interface (`SigningScheme`) that abstracts curve-specific implementations
- Both curve packages implement this interface for interchangeable usage

### Keystore System
- `pkg/keystore/` - EIP-2335 compliant encrypted keystore with multi-curve support
- `pkg/keystore/legacy/` - Legacy keystore format support for migration

### Key Design Patterns
- **Strategy Pattern**: `SigningScheme` interface allows pluggable curve implementations
- **Factory Pattern**: `GetSigningSchemeForCurveType()` creates appropriate scheme instances
- **Adapter Pattern**: Legacy keystore conversion to EIP-2335 format

## Common Development Commands

```bash
# Install dependencies and tools
make deps

# Run all tests with proper isolation
make test

# Lint the code
make lint

# Format code  
make fmt

# Check formatting without modifying files
make fmtcheck
```

## Testing Individual Packages

```bash
# Test specific package
go test -v ./pkg/bls381/
go test -v ./pkg/bn254/
go test -v ./pkg/keystore/

# Run integration tests
go test -v ./pkg/integration/
```

## Key Implementation Notes

- Both curve implementations support key generation, signing, verification, and signature aggregation
- BLS12-381 includes EIP-2333 hierarchical deterministic key derivation  
- BN254 includes Ethereum precompile format compatibility
- Keystores use password normalization per EIP-2335 (NFKD + control code stripping)
- All implementations support batch verification for performance optimization

## Dependencies

- `github.com/consensys/gnark-crypto` - Core elliptic curve operations
- `github.com/ethereum/go-ethereum` - Ethereum compatibility
- `golang.org/x/crypto` - Cryptographic primitives for keystore encryption