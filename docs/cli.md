# CLI Documentation

This document explains how to use the Enigma-Go command-line interface for cryptographic operations.

## Installation and Building

### Running with Go

You can run the CLI directly using Go:

```bash
go run main.go [command] [options]
```

### Building the Executable

To build a standalone executable:

```bash
go build -o enigma.exe main.go
```

Then run:

```bash
./enigma.exe [command] [options]
```

## Available Commands

### Device Status Commands

#### Version

Get the API version of the connected device.

```bash
enigma.exe version
```

#### Detect Device

Check if a compatible hardware device is connected.

```bash
enigma.exe detect-device
```

#### Get Device UID

Retrieve the unique identifier of the connected device.

```bash
enigma.exe uid
```

### Authentication Commands

#### Login Status

Check the current login status of the device.

```bash
enigma.exe login-status
```

#### Login

Authenticate with the device using a PIN.

```bash
enigma.exe login --pin "123456"
```

#### Change PIN

Change the device PIN.

```bash
enigma.exe change-pin --old-pin "123456" --new-pin "654321"
```

### AES Encryption Commands

#### AES Encrypt String

Encrypt a text string using AES.

```bash
enigma.exe aes-encrypt --message "Hello, World!"
```

#### AES Decrypt String

Decrypt an AES-encrypted string.

```bash
enigma.exe aes-decrypt --cipher "encrypted_data_here"
```

#### AES Encrypt File

Encrypt a file using AES.

```bash
enigma.exe aes-encrypt-file --source-path "/path/to/source/" --source-name "document.txt" --target-path "/path/to/target/"
```

#### AES Decrypt File

Decrypt an AES-encrypted file.

```bash
enigma.exe aes-decrypt-file --source-path "/path/to/source/" --source-name "document.txt.enc" --target-path "/path/to/target/"
```

### RSA Operations

#### Generate RSA Key Pair

Generate a new RSA key pair on the device.

```bash
enigma.exe generate-key --custom-id "mykey001"
```

#### Import External Public Key

Import an external RSA public key.

```bash
enigma.exe import-key --custom-id "extkey01" --pub-key-n "base64_encoded_n" --pub-key-e "base64_encoded_e"
```

#### Set Transmission Key

Set a public key for secure transmission.

```bash
enigma.exe set-trans-key --pub-key-n "base64_encoded_n" --pub-key-e "base64_encoded_e"
```

#### RSA Encrypt

Encrypt a message using RSA.

```bash
enigma.exe rsa-encrypt --key-id "mykey001" --message "Secret message"
```

#### RSA Decrypt

Decrypt an RSA-encrypted message.

```bash
enigma.exe rsa-decrypt --key-id "mykey001" --cipher "base64_encoded_cipher"
```

#### Digital Signature

Create a digital signature for a message.

```bash
enigma.exe sign --key-id "mykey001" --message "Message to sign"
```

#### Verify Signature

Verify a digital signature.

```bash
enigma.exe verify --key-id "mykey001" --message "Original message" --signature "base64_encoded_signature"
```

#### List All Keys

List all RSA keys stored on the device.

```bash
enigma.exe list-keys
```

#### Delete Key

Delete a specific RSA key from the device.

```bash
enigma.exe delete-key --key-id "mykey001"
```

#### Reset All Keys

Delete all RSA keys from the device.

```bash
enigma.exe reset-keys
```

## Output Format

All commands return JSON-formatted output with the following structure:

### Success Response

```json
{
  "status": "success",
  "data": {
    // Command-specific data
  }
}
```

### Error Response

```json
{
  "status": "error",
  "message": "Error description"
}
```

## Usage Examples

### Complete AES Workflow

```bash
# 1. Check device status
enigma.exe detect-device

# 2. Login to device
enigma.exe login --pin "123456"

# 3. Encrypt a message
enigma.exe aes-encrypt --message "Confidential data"

# 4. Decrypt the message (using cipher from step 3)
enigma.exe aes-decrypt --cipher "encrypted_output_from_step_3"
```

### Complete RSA Workflow

```bash
# 1. Login to device
enigma.exe login --pin "123456"

# 2. Generate RSA key pair
enigma.exe generate-key --custom-id "testkey"

# 3. Encrypt a message
enigma.exe rsa-encrypt --key-id "testkey" --message "Secret information"

# 4. Sign a message
enigma.exe sign --key-id "testkey" --message "Document to sign"

# 5. List all keys
enigma.exe list-keys

# 6. Delete the key
enigma.exe delete-key --key-id "testkey"
```

## Error Handling

The CLI provides detailed error messages for common issues:

- **Device not found**: Ensure the hardware security module is properly connected
- **Login failed**: Verify the PIN is correct and the device is not locked
- **Key not found**: Check that the specified key ID exists using `list-keys`
- **File not found**: Verify file paths are correct and accessible
