//go:build windows

package main

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"testing"

	"github.com/joshimello/enigma-go/enigma"
)

// Helper function to load the DLL using the shared initialization
func loadTestDLL(t *testing.T) *syscall.DLL {
	return InitTestLibrary(t)
}

func TestAESEncryptBlock(t *testing.T) {
	dll := loadTestDLL(t)
	defer dll.Release()

	// Test with a known 16-byte block
	testBlock := [16]byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}

	t.Logf("Input block: %s", hex.EncodeToString(testBlock[:]))

	// Encrypt the block
	encrypted, err := enigma.AESEncryptBlock(dll, testBlock)
	if err != nil {
		t.Fatalf("AESEncryptBlock failed: %v", err)
	}

	t.Logf("Encrypted block: %s", hex.EncodeToString(encrypted[:]))

	// The encrypted block should be different from the input
	if encrypted == testBlock {
		t.Error("Encrypted block is the same as input block - encryption may not be working")
	}

	// The encrypted block should be exactly 16 bytes
	if len(encrypted) != 16 {
		t.Errorf("Expected 16 bytes, got %d", len(encrypted))
	}
}

func TestAESDecryptBlock(t *testing.T) {
	dll := loadTestDLL(t)
	defer dll.Release()

	// Test with a known 16-byte block
	testBlock := [16]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	t.Logf("Original block: %s", hex.EncodeToString(testBlock[:]))

	// Encrypt the block first
	encrypted, err := enigma.AESEncryptBlock(dll, testBlock)
	if err != nil {
		t.Fatalf("AESEncryptBlock failed: %v", err)
	}

	t.Logf("Encrypted block: %s", hex.EncodeToString(encrypted[:]))

	// Now decrypt it
	decrypted, err := enigma.AESDecryptBlock(dll, encrypted)
	if err != nil {
		t.Fatalf("AESDecryptBlock failed: %v", err)
	}

	t.Logf("Decrypted block: %s", hex.EncodeToString(decrypted[:]))

	// The decrypted block should match the original
	if decrypted != testBlock {
		t.Errorf("Decrypted block doesn't match original")
		t.Errorf("Expected: %s", hex.EncodeToString(testBlock[:]))
		t.Errorf("Got:      %s", hex.EncodeToString(decrypted[:]))
	}
}

func TestAESBlockDeterministic(t *testing.T) {
	dll := loadTestDLL(t)
	defer dll.Release()

	// Test block
	testBlock := [16]byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}

	// Encrypt the same block multiple times
	encrypted1, err := enigma.AESEncryptBlock(dll, testBlock)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := enigma.AESEncryptBlock(dll, testBlock)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	encrypted3, err := enigma.AESEncryptBlock(dll, testBlock)
	if err != nil {
		t.Fatalf("Third encryption failed: %v", err)
	}

	// All results should be identical (deterministic)
	if encrypted1 != encrypted2 {
		t.Error("Encryption is not deterministic - first and second results differ")
	}

	if encrypted1 != encrypted3 {
		t.Error("Encryption is not deterministic - first and third results differ")
	}

	if encrypted2 != encrypted3 {
		t.Error("Encryption is not deterministic - second and third results differ")
	}

	t.Logf("All three encryptions produced identical results: %s", hex.EncodeToString(encrypted1[:]))
}

func TestAESBlockZeroInput(t *testing.T) {
	dll := loadTestDLL(t)
	defer dll.Release()

	// Test with all zeros
	zeroBlock := [16]byte{}

	t.Logf("Zero block: %s", hex.EncodeToString(zeroBlock[:]))

	encrypted, err := enigma.AESEncryptBlock(dll, zeroBlock)
	if err != nil {
		t.Fatalf("AESEncryptBlock with zero input failed: %v", err)
	}

	t.Logf("Encrypted zero block: %s", hex.EncodeToString(encrypted[:]))

	// The encrypted block should not be all zeros (unless using a zero key, which is unlikely)
	allZeros := [16]byte{}
	if encrypted == allZeros {
		t.Logf("Warning: Encrypted zero block is still all zeros - this might indicate an issue")
	}

	// Decrypt and verify
	decrypted, err := enigma.AESDecryptBlock(dll, encrypted)
	if err != nil {
		t.Fatalf("AESDecryptBlock failed: %v", err)
	}

	if decrypted != zeroBlock {
		t.Errorf("Decrypted zero block doesn't match original")
		t.Errorf("Expected: %s", hex.EncodeToString(zeroBlock[:]))
		t.Errorf("Got:      %s", hex.EncodeToString(decrypted[:]))
	}
}

func TestAESBlockMaxInput(t *testing.T) {
	dll := loadTestDLL(t)
	defer dll.Release()

	// Test with all 0xFF bytes
	maxBlock := [16]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}

	t.Logf("Max block: %s", hex.EncodeToString(maxBlock[:]))

	encrypted, err := enigma.AESEncryptBlock(dll, maxBlock)
	if err != nil {
		t.Fatalf("AESEncryptBlock with max input failed: %v", err)
	}

	t.Logf("Encrypted max block: %s", hex.EncodeToString(encrypted[:]))

	// Decrypt and verify
	decrypted, err := enigma.AESDecryptBlock(dll, encrypted)
	if err != nil {
		t.Fatalf("AESDecryptBlock failed: %v", err)
	}

	if decrypted != maxBlock {
		t.Errorf("Decrypted max block doesn't match original")
		t.Errorf("Expected: %s", hex.EncodeToString(maxBlock[:]))
		t.Errorf("Got:      %s", hex.EncodeToString(decrypted[:]))
	}
}

// Benchmark function to test performance
func BenchmarkAESEncryptBlock(b *testing.B) {
	// Convert *testing.B to *testing.T for InitTestLibrary
	t := &testing.T{}
	dll := loadTestDLL(t)
	defer dll.Release()

	testBlock := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := enigma.AESEncryptBlock(dll, testBlock)
		if err != nil {
			b.Fatalf("Benchmark failed: %v", err)
		}
	}
}

// Example function showing how to use the block functions
func ExampleAESEncryptBlock() {
	t := &testing.T{}
	dll := loadTestDLL(t)
	defer dll.Release()

	// Example 16-byte block
	plaintext := [16]byte{
		0x32, 0x88, 0x31, 0xe0, 0x43, 0x5a, 0x31, 0x37,
		0xf6, 0x30, 0x98, 0x07, 0xa8, 0x8d, 0xa2, 0x34,
	}

	// Encrypt the block
	encrypted, err := enigma.AESEncryptBlock(dll, plaintext)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}

	// Decrypt the block
	decrypted, err := enigma.AESDecryptBlock(dll, encrypted)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}

	fmt.Printf("Original:  %x\n", plaintext)
	fmt.Printf("Encrypted: %x\n", encrypted)
	fmt.Printf("Decrypted: %x\n", decrypted)
	fmt.Printf("Match: %v\n", plaintext == decrypted)
}
