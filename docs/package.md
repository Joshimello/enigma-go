# Package Documentation

This document explains how to install and use the Enigma-Go library in your Go projects.

## Installation

Install the library using Go modules:

```bash
go get github.com/joshimello/enigma-go
```

## Import

Import the enigma package in your Go code:

```go
import "github.com/joshimello/enigma-go/enigma"
```

## Available Functions

The enigma package provides the following cryptographic functions:

### Hardware Management

#### `Create(dllPath string) (*syscall.DLL, error)`

Creates a connection to the hardware security module using the specified DLL path.

#### `Detect(dll *syscall.DLL) (bool, error)`

Detects if a compatible hardware device is connected.

#### `Version(dll *syscall.DLL) (bool, string, error)`

Returns the API version of the connected device.

#### `UID(dll *syscall.DLL) (bool, string, error)`

Gets the unique identifier of the connected device.

### Authentication

#### `LoginStatus(dll *syscall.DLL) (bool, int, bool, error)`

Checks the current login status and returns login state, retry count, and lock status.

#### `Login(dll *syscall.DLL, pin string) (bool, error)`

Authenticates with the device using a PIN.

#### `ChangePin(dll *syscall.DLL, oldPin string, newPin string) (bool, error)`

Changes the device PIN from old to new PIN.

### AES Operations

#### `AESEncrypt(dll *syscall.DLL, inputStr string) (string, error)`

Encrypts a string using AES encryption.

#### `AESDecrypt(dll *syscall.DLL, inputStr string) (string, error)`

Decrypts an AES-encrypted string.

#### `AESEncryptBytes(dll *syscall.DLL, inputData []byte) ([]byte, error)`

Encrypts byte data using AES encryption.

#### `AESDecryptBytes(dll *syscall.DLL, inputData []byte) ([]byte, error)`

Decrypts AES-encrypted byte data.

#### `AESEncryptFile(dll *syscall.DLL, sourceFilePath, sourceFileName, targetPath string) error`

Encrypts a file using AES encryption.

#### `AESDecryptFile(dll *syscall.DLL, sourceFilePath, sourceFileName, targetPath string) error`

Decrypts an AES-encrypted file.

### RSA Operations

#### `GenerateKey(dll *syscall.DLL, customID string) (bool, string, string, string, error)`

Generates an RSA key pair and returns success status, key ID, public key N, and public key E.

#### `ImportKey(dll *syscall.DLL, customID string, pubKeyN string, pubKeyE string) (bool, string, error)`

Imports an external RSA public key.

#### `SetTransKey(dll *syscall.DLL, pubKeyN string, pubKeyE string) (bool, string, error)`

Sets a transmission public key for secure communication.

#### `RSAEncrypt(dll *syscall.DLL, keyID string, message string) (bool, string, error)`

Encrypts a message using RSA encryption.

#### `RSADecrypt(dll *syscall.DLL, keyID string, cipher string) (bool, string, error)`

Decrypts an RSA-encrypted message.

#### `Sign(dll *syscall.DLL, keyID string, message string) (bool, string, error)`

Creates a digital signature for a message.

#### `SignBytes(dll *syscall.DLL, keyID string, messageBytes []byte) (bool, []byte, error)`

Creates a digital signature for byte data.

#### `Verify(dll *syscall.DLL, keyID string, message string, signature string) (bool, bool, error)`

Verifies a digital signature.

#### `DeleteKey(dll *syscall.DLL, keyID string) (bool, error)`

Deletes an RSA key from the device.

#### `ListKeys(dll *syscall.DLL) (bool, uint8, []string, []string, error)`

Lists all stored RSA keys and returns key count, key IDs, and custom IDs.

#### `ResetKeys(dll *syscall.DLL) (bool, error)`

Deletes all RSA keys from the device.

### XMSS Operations (Post-Quantum Cryptography)

#### `XMSSGetParam(dll *syscall.DLL) (*XMSSParam, error)`

Gets XMSS parameters from the device.

#### `XMSSKeyGen(dll *syscall.DLL, isXMSSMT bool, oidStr string, skeyFile string, pkeyFile string) error`

Generates XMSS key pairs and saves them to files.

#### `XMSSSign(dll *syscall.DLL, skeyFile, msgFile, sigFile string) error`

Creates an XMSS signature for a message file.

#### `XMSSVerify(dll *syscall.DLL, pkeyFile, sigFile string) error`

Verifies an XMSS signature.

## Usage Example

```go
package main

import (
    "fmt"
    "github.com/joshimello/enigma-go/enigma"
)

func main() {
    // Create connection to hardware device
    dll, err := enigma.Create("library/EnovaMX.dll")
    if err != nil {
        fmt.Printf("Failed to create connection: %v\n", err)
        return
    }

    // Detect device
    detected, err := enigma.Detect(dll)
    if err != nil || !detected {
        fmt.Printf("Device not detected: %v\n", err)
        return
    }

    // Login with PIN
    success, err := enigma.Login(dll, "123456")
    if err != nil || !success {
        fmt.Printf("Login failed: %v\n", err)
        return
    }

    // Encrypt a message
    plaintext := "Hello, World!"
    ciphertext, err := enigma.AESEncrypt(dll, plaintext)
    if err != nil {
        fmt.Printf("Encryption failed: %v\n", err)
        return
    }

    // Decrypt the message
    decrypted, err := enigma.AESDecrypt(dll, ciphertext)
    if err != nil {
        fmt.Printf("Decryption failed: %v\n", err)
        return
    }

    fmt.Printf("Original: %s\n", plaintext)
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

## Error Handling

The library includes comprehensive error handling with descriptive error messages. Use the `GetCodeMessage(code uint8) string` function to get human-readable error descriptions for device-specific error codes.
