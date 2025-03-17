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
	encryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return "", err
	}

	data := []byte(inputStr)
	paddedData := ISO9797_1_Method2Padding(data, 16)

	requiredSectors := (len(paddedData) + sectorSize - 1) / sectorSize
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
		return "", fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	// return hex.EncodeToString(outputBuffer[:len(paddedData)]), nil
	return string(outputBuffer[:len(paddedData)]), nil
}

func AESDecrypt(dll *syscall.DLL, inputStr string) (string, error) {
	decryptProc, err := dll.FindProc("AESStreamEncDec")
	if err != nil {
		return "", err
	}

	data := []byte(inputStr)

	requiredSectors := (len(data) + sectorSize - 1) / sectorSize
	bufferSize := requiredSectors * sectorSize

	inputBuffer := make([]byte, bufferSize)
	copy(inputBuffer, data)
	outputBuffer := make([]byte, bufferSize)

	r1, _, _ := decryptProc.Call(
		uintptr(unsafe.Pointer(&inputBuffer[0])),
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(requiredSectors),
		uintptr(0),
	)

	if r1 != 0 {
		return "", fmt.Errorf("%s", GetCodeMessage(uint8(r1)))
	}

	unpaddedData := ISO9797_1_Method2Unpadding(outputBuffer[:len(data)])

	return string(unpaddedData), nil
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
