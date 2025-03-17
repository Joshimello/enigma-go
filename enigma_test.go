//go:build windows

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/joshimello/enigma-go/enigma"
)

func RandomString(length int) string {
	bytes := make([]byte, length)
	const minRune = 0x4E00
	const maxRune = 0x9FFF
	for i := 0; i < length; {
		r := rune(rand.Intn(maxRune-minRune+1) + minRune)
		if utf8.ValidRune(r) {
			count := utf8.RuneLen(r)
			if i+count <= length {
				utf8.EncodeRune(bytes[i:], r)
				i += count
			} else {
				break
			}
		}
	}
	return string(bytes[:length])
}

func TestAESData(t *testing.T) {
	dll, err := enigma.Create()
	if err != nil {
		t.Error(err)
	}

	detectRes, err := enigma.Detect(dll)
	if !detectRes || err != nil {
		t.Error(err)
	}

	loginRes, err := enigma.Login(dll, "000000")
	if !loginRes || err != nil {
		t.Error(err)
	}

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

	dll, err := enigma.Create()
	if err != nil {
		t.Fatal("Failed to create DLL:", err)
	}

	detectRes, err := enigma.Detect(dll)
	if !detectRes || err != nil {
		t.Fatal("Failed to detect device:", err)
	}

	loginRes, err := enigma.Login(dll, "000000")
	if !loginRes || err != nil {
		t.Fatal("Failed to login:", err)
	}

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
