# Enigma-Go

A Go library and CLI tool for cryptographic operations using hardware security modules (HSM).

## Features

- **AES Encryption/Decryption**: Stream and file-based operations
- **RSA Operations**: Key generation, encryption, decryption, signing, and verification
- **XMSS Support**: Post-quantum cryptographic signatures
- **CLI Interface**: Command-line tool for all operations
- **Go Library**: Easy integration into Go applications

## Quick Start

### Installation

```bash
go get github.com/joshimello/enigma-go
```

### Usage

```go
import "github.com/joshimello/enigma-go/enigma"
```

## Documentation

- **[Package Documentation](docs/package.md)** - How to install and use the library in your Go projects
- **[CLI Documentation](docs/cli.md)** - Command-line interface usage and examples
- **[Benchmark Results](docs/benchmark.md)** - Performance testing and optimization data

## Requirements

- Go 1.24.1 or later
- Windows (current build target)
- Compatible hardware security module

## License

This project is licensed under the MIT License.
