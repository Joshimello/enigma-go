//go:build windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshimello/enigma-go/enigma"
)

func TestAESData(t *testing.T) {
	dll := InitTestLibrary(t)

	testString := RandomString(2048)
	fmt.Println(testString)

	encRes, err := enigma.AESEncrypt(dll, testString)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(encRes)

	decRes, err := enigma.AESDecrypt(dll, encRes)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(decRes)

	if decRes != testString {
		t.Error("Decrypted string does not match original string")
	}
}

func TestAESFile(t *testing.T) {
	dll := InitTestLibrary(t)

	tempDir, err := os.MkdirTemp("", "enigma_test")
	if err != nil {
		t.Fatal("Failed to create temp directory:", err)
	}
	defer os.RemoveAll(tempDir)

	srcDir := filepath.Join(tempDir, "source")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal("Failed to create source directory:", err)
	}

	destDir := filepath.Join(tempDir, "dest")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatal("Failed to create destination directory:", err)
	}

	sourceFilePath := filepath.Join(srcDir, "test.txt")
	fileName := "test.txt"
	content := []byte(RandomString(2048))
	if err := os.WriteFile(sourceFilePath, content, 0644); err != nil {
		t.Fatal("Failed to create test file:", err)
	}

	fmt.Println(string(content))

	fmt.Println(srcDir)
	fmt.Println(fileName)
	fmt.Println(destDir)

	encryptedFilePath := filepath.Join(destDir, "test.txt.emx")
	encryptErr := enigma.AESEncryptFile(dll, srcDir, "./"+fileName, destDir)
	if encryptErr != nil {
		t.Fatal("Failed to encrypt file:", encryptErr)
	}

	if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
		t.Fatal("Encrypted file not created")
	}

	encryptedContent, err := os.ReadFile(encryptedFilePath)
	if err != nil {
		t.Fatal("Failed to read encrypted file:", err)
	}

	fmt.Println(string(encryptedContent))

	decryptedFilePath := filepath.Join(tempDir, "decrypted")
	if err := os.MkdirAll(decryptedFilePath, 0755); err != nil {
		t.Fatal("Failed to create decrypted directory:", err)
	}

	fmt.Println(destDir)
	fmt.Println(filepath.Base(encryptedFilePath))
	fmt.Println(decryptedFilePath)

	decryptErr := enigma.AESDecryptFile(dll, destDir, "./"+filepath.Base(encryptedFilePath), decryptedFilePath)
	if decryptErr != nil {
		t.Fatal("Failed to decrypt file:", decryptErr)
	}

	decryptedFileName := filepath.Join(decryptedFilePath, fileName)
	if _, err := os.Stat(decryptedFileName); os.IsNotExist(err) {
		t.Fatal("Decrypted file not created")
	}

	decryptedContent, err := os.ReadFile(decryptedFileName)
	if err != nil {
		t.Fatal("Failed to read decrypted file:", err)
	}

	fmt.Println(string(decryptedContent))

	if !bytes.Equal(content, decryptedContent) {
		t.Fatal("Decrypted content does not match original content")
	}
}
