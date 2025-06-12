//go:build windows

package main

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/joshimello/enigma-go/enigma"
)

// generateRandomData creates random byte data of specified size
func generateRandomData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	return data
}

// TestAESBenchmark tests AES encryption from 1 byte to 1GB
func TestAESBenchmark(t *testing.T) {
	// Initialize the library
	dll, err := enigma.Create("../library/EnovaMX.dll")
	if err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	detectRes, err := enigma.Detect(dll)
	if !detectRes || err != nil {
		t.Fatalf("Device detection failed: %v", err)
	}

	loginRes, err := enigma.Login(dll, "000000")
	if !loginRes || err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test sizes from 1 byte to 1GB
	testSizes := []int{
		1,
		10,
		100,
		1000,      // 1KB
		10000,     // 10KB
		100000,    // 100KB
		1000000,   // 1MB
		10000000,  // 10MB
		100000000, // 100MB
		500000000, // 1GB
	}

	fmt.Printf("\n=== AES Encryption Benchmark ===\n")
	fmt.Printf("%-12s %-15s\n", "Data Size", "Avg Time (3 runs)")
	fmt.Printf("%-12s %-15s\n", "---------", "----------------")

	for _, size := range testSizes {
		// Generate random test data
		testData := generateRandomData(size)

		var totalTime time.Duration
		var success bool = true

		// Run 3 times and calculate average
		for run := 0; run < 3; run++ {
			start := time.Now()

			// Encrypt
			encryptedData, err := enigma.AESEncryptBytes(dll, testData)
			if err != nil {
				t.Errorf("Encryption failed for size %s: %v", formatSize(size), err)
				success = false
				break
			}

			// Decrypt to verify correctness (not timed)
			decryptedData, err := enigma.AESDecryptBytes(dll, encryptedData)
			if err != nil {
				t.Errorf("Decryption failed for size %s: %v", formatSize(size), err)
				success = false
				break
			}

			// Verify data integrity
			if len(decryptedData) != len(testData) {
				t.Errorf("Data length mismatch for size %s", formatSize(size))
				success = false
				break
			}

			elapsed := time.Since(start)
			totalTime += elapsed
		}

		if success {
			avgTime := totalTime / 3
			fmt.Printf("%-12s %-15s\n", formatSize(size), avgTime.String())
		} else {
			fmt.Printf("%-12s %-15s\n", formatSize(size), "FAILED")
		}
	}
}

// formatSize formats byte count into human-readable string
func formatSize(bytes int) string {
	if bytes < 1000 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1000000 {
		return fmt.Sprintf("%d KB", bytes/1000)
	} else if bytes < 1000000000 {
		return fmt.Sprintf("%d MB", bytes/1000000)
	} else {
		return fmt.Sprintf("%d GB", bytes/1000000000)
	}
}
