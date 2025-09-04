//go:build windows

package enigma

import (
	"fmt"
	"syscall"
	"unsafe"
)

const sectorSize = 512

func ISO9797_1_Method2Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	paddingBytes := make([]byte, padding)
	paddingBytes[0] = 0x80
	return append(data, paddingBytes...)
}

func ISO9797_1_Method2Unpadding(data []byte) []byte {
	index := len(data) - 1
	for index >= 0 && data[index] == 0 {
		index--
	}

	if index < 0 || data[index] != 0x80 {
		return data
	}

	return data[:index]
}

func AESEncrypt(dll *syscall.DLL, inputStr string) (string, error) {
	paddedData := ISO9797_1_Method2Padding([]byte(inputStr), 16)
	encryptedBytes, err := AESEncryptBytes(dll, paddedData)
	if err != nil {
		return "", err
	}

	// return hex.EncodeToString(encryptedBytes[:len(paddedData)]), nil
	return string(encryptedBytes[:len(paddedData)]), nil
}

func AESEncryptBytes(dll *syscall.DLL, inputData []byte) ([]byte, error) {
	encryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return nil, err
	}

	paddedData := ISO9797_1_Method2Padding(inputData, 16)

	requiredSectors := (len(inputData) + sectorSize - 1) / sectorSize
	bufferSize := requiredSectors * sectorSize

	inputBuffer := make([]byte, bufferSize)
	copy(inputBuffer, paddedData)
	outputBuffer := make([]byte, bufferSize)

	r1, _, _ := encryptProc.Call(
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(requiredSectors),
		uintptr(1),
	)

	if r1 != 0 {
		return nil, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return outputBuffer[:len(paddedData)], nil
}

func AESDecryptBytes(dll *syscall.DLL, inputData []byte) ([]byte, error) {
	decryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return nil, err
	}

	requiredSectors := (len(inputData) + sectorSize - 1) / sectorSize
	bufferSize := requiredSectors * sectorSize

	inputBuffer := make([]byte, bufferSize)
	copy(inputBuffer, inputData)
	outputBuffer := make([]byte, bufferSize)

	r1, _, _ := decryptProc.Call(
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(requiredSectors),
		uintptr(0),
	)

	if r1 != 0 {
		return nil, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	unpaddedData := ISO9797_1_Method2Unpadding(outputBuffer[:len(inputData)])

	return unpaddedData, nil
}

func AESDecrypt(dll *syscall.DLL, inputStr string) (string, error) {
	decryptedBytes, err := AESDecryptBytes(dll, []byte(inputStr))
	if err != nil {
		return "", err
	}

	return string(decryptedBytes), nil
}

func AESEncryptFile(dll *syscall.DLL, sourceFilePath, sourceFileName, targetPath string) error {
	fileAESProc, err := dll.FindProc("FileAES")
	if err != nil {
		return err
	}

	sourceFilePathBytes := append([]byte(sourceFilePath), 0)
	sourceFileNameBytes := append([]byte(sourceFileName), 0)
	targetPathBytes := append([]byte(targetPath), 0)

	r1, _, _ := fileAESProc.Call(
		uintptr(unsafe.Pointer(&sourceFilePathBytes[0])),
		uintptr(unsafe.Pointer(&sourceFileNameBytes[0])),
		uintptr(unsafe.Pointer(&targetPathBytes[0])),
		uintptr(1),
	)

	if r1 != 0 {
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return nil
}

func AESEncryptBlock(dll *syscall.DLL, plaintext [16]byte) ([16]byte, error) {
	encryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return [16]byte{}, err
	}

	// Create 512-byte buffers (one sector)
	inputBuffer := make([]byte, sectorSize)
	outputBuffer := make([]byte, sectorSize)

	// Copy the 16-byte block to the beginning of the input buffer
	copy(inputBuffer[:16], plaintext[:])
	// The rest of the buffer will be zeros

	r1, _, _ := encryptProc.Call(
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(1), // 1 sector
		uintptr(1), // 1 = encrypt
	)

	if r1 != 0 {
		return [16]byte{}, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	// Extract the first 16 bytes from the output
	var result [16]byte
	copy(result[:], outputBuffer[:16])
	return result, nil
}

// AESDecryptBlock decrypts a single 16-byte AES block using the HSM
func AESDecryptBlock(dll *syscall.DLL, ciphertext [16]byte) ([16]byte, error) {
	decryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return [16]byte{}, err
	}

	// Create 512-byte buffers (one sector)
	inputBuffer := make([]byte, sectorSize)
	outputBuffer := make([]byte, sectorSize)

	// Copy the 16-byte block to the beginning of the input buffer
	copy(inputBuffer[:16], ciphertext[:])
	// The rest of the buffer will be zeros

	r1, _, _ := decryptProc.Call(
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(1), // 1 sector
		uintptr(0), // 0 = decrypt
	)

	if r1 != 0 {
		return [16]byte{}, fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	// Extract the first 16 bytes from the output
	var result [16]byte
	copy(result[:], outputBuffer[:16])
	return result, nil
}

func AESDecryptFile(dll *syscall.DLL, sourceFilePath, sourceFileName, targetPath string) error {
	fileAESProc, err := dll.FindProc("FileAES")
	if err != nil {
		return err
	}

	sourceFilePathBytes := append([]byte(sourceFilePath), 0)
	sourceFileNameBytes := append([]byte(sourceFileName), 0)
	targetPathBytes := append([]byte(targetPath), 0)

	r1, _, _ := fileAESProc.Call(
		uintptr(unsafe.Pointer(&sourceFilePathBytes[0])),
		uintptr(unsafe.Pointer(&sourceFileNameBytes[0])),
		uintptr(unsafe.Pointer(&targetPathBytes[0])),
		uintptr(0), // enc=0 for decryption
	)

	if r1 != 0 {
		return fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	return nil
}
