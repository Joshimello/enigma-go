//go:build windows

package main

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/joshimello/enigma-go/enigma"
)

// BenchmarkResult holds the results for a specific test
type BenchmarkResult struct {
	Operation string
	DataSize  string
	TotalTime time.Duration
	AvgTimeMs float64
	Success   bool
}

// generateRandomData creates random byte data of specified size
func generateRandomData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(rand.Intn(256))
	}
	return data
}

// formatSize formats byte count into human-readable string
func formatSize(bytes int) string {
	if bytes < 1000 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1000000 {
		return fmt.Sprintf("%d KB", bytes/1000)
	} else {
		return fmt.Sprintf("%d MB", bytes/1000000)
	}
}

// runBenchmark runs a benchmark operation multiple times and returns results
func runBenchmark(operation string, dataSize int, runs int, testFunc func() error) BenchmarkResult {
	result := BenchmarkResult{
		Operation: operation,
		DataSize:  formatSize(dataSize),
		Success:   true,
	}

	var totalTime time.Duration

	for i := 0; i < runs; i++ {
		start := time.Now()
		err := testFunc()
		elapsed := time.Since(start)

		if err != nil {
			result.Success = false
			fmt.Printf("Error in %s with size %s: %v\n", operation, result.DataSize, err)
			break
		}

		totalTime += elapsed
	}

	result.TotalTime = totalTime
	if result.Success {
		result.AvgTimeMs = float64(totalTime.Nanoseconds()) / float64(runs) / 1000000.0
	}

	return result
}

// TestComprehensiveBenchmark tests all encryption operations
func TestComprehensiveBenchmark(t *testing.T) {
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

	// Generate RSA key pair for testing
	keyGenSuccess, keyID, pubKeyN, pubKeyE, err := enigma.GenerateKey(dll, "TESTKEY1")
	if !keyGenSuccess || err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Import the public key for encryption
	importSuccess, encKeyID, err := enigma.ImportKey(dll, "TESTKEY2", pubKeyN, pubKeyE)
	if !importSuccess || err != nil {
		t.Fatalf("Failed to import RSA key: %v", err)
	}

	// Test data sizes
	testSizes := []int{
		10,
		500,
		1000,    // 1KB
		5000,    // 5KB
		10000,   // 10KB
		100000,  // 100KB
		1000000, // 1MB
	}

	const runs = 100
	var results []BenchmarkResult

	fmt.Printf("\n=== Comprehensive Cryptographic Benchmark ===\n")
	fmt.Printf("Running %d iterations for each test...\n\n", runs)

	// Test AES Stream Encryption
	fmt.Printf("Testing AES Stream Encryption...\n")
	for _, size := range testSizes {
		testData := generateRandomData(size)

		result := runBenchmark("AES Stream Enc", size, runs, func() error {
			_, err := enigma.AESEncryptBytes(dll, testData)
			return err
		})
		results = append(results, result)

		if result.Success {
			fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
		} else {
			fmt.Printf("  %s: FAILED\n", result.DataSize)
		}
	}

	// Test AES Stream Decryption
	fmt.Printf("\nTesting AES Stream Decryption...\n")
	for _, size := range testSizes {
		testData := generateRandomData(size)
		encryptedData, err := enigma.AESEncryptBytes(dll, testData)
		if err != nil {
			t.Errorf("Failed to encrypt data for decryption test: %v", err)
			continue
		}

		result := runBenchmark("AES Stream Dec", size, runs, func() error {
			_, err := enigma.AESDecryptBytes(dll, encryptedData)
			return err
		})
		results = append(results, result)

		if result.Success {
			fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
		} else {
			fmt.Printf("  %s: FAILED\n", result.DataSize)
		}
	}

	// Test RSA Encryption (limited by RSA key size)
	fmt.Printf("\nTesting RSA Encryption...\n")
	for _, size := range testSizes {
		// RSA has size limitations, typically can encrypt up to (key_size - padding) bytes
		// For 2048-bit RSA with PKCS#1 v1.5 padding, max is about 245 bytes
		if size > 245 {
			fmt.Printf("  %s: SKIPPED (exceeds RSA size limit)\n", formatSize(size))
			continue
		}

		testData := generateRandomData(size)
		testMessage := string(testData)

		result := runBenchmark("RSA Enc", size, runs, func() error {
			success, _, err := enigma.RSAEncrypt(dll, encKeyID, testMessage)
			if !success {
				return fmt.Errorf("RSA encryption failed")
			}
			return err
		})
		results = append(results, result)

		if result.Success {
			fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
		} else {
			fmt.Printf("  %s: FAILED\n", result.DataSize)
		}
	}

	// Test RSA Decryption
	fmt.Printf("\nTesting RSA Decryption...\n")
	for _, size := range testSizes {
		if size > 245 {
			fmt.Printf("  %s: SKIPPED (exceeds RSA size limit)\n", formatSize(size))
			continue
		}

		testData := generateRandomData(size)
		testMessage := string(testData)

		// First encrypt the message
		success, encryptedMessage, err := enigma.RSAEncrypt(dll, encKeyID, testMessage)
		if !success || err != nil {
			t.Errorf("Failed to encrypt message for decryption test: %v", err)
			continue
		}

		result := runBenchmark("RSA Dec", size, runs, func() error {
			success, _, err := enigma.RSADecrypt(dll, keyID, encryptedMessage)
			if !success {
				return fmt.Errorf("RSA decryption failed")
			}
			return err
		})
		results = append(results, result)

		if result.Success {
			fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
		} else {
			fmt.Printf("  %s: FAILED\n", result.DataSize)
		}
	}

	// Test RSA Sign (only 190 bytes as requested)
	fmt.Printf("\nTesting RSA Sign...\n")
	signData := generateRandomData(190)
	var signatureData []byte

	result := runBenchmark("RSA Sign", 190, runs, func() error {
		success, signature, err := enigma.SignBytes(dll, keyID, signData)
		if !success {
			return fmt.Errorf("RSA signing failed")
		}
		signatureData = signature
		return err
	})
	results = append(results, result)

	if result.Success {
		fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
	} else {
		fmt.Printf("  %s: FAILED\n", result.DataSize)
	}

	// Test RSA Verify (verify the signed data from above)
	fmt.Printf("\nTesting RSA Verify...\n")
	if len(signatureData) > 0 {
		signMessage := string(signData)
		// First create a signature to verify
		success, signatureStr, err := enigma.Sign(dll, keyID, signMessage)
		if !success || err != nil {
			t.Errorf("Failed to create signature for verify test: %v", err)
		} else {
			result := runBenchmark("RSA Verify", 190, runs, func() error {
				success, verified, err := enigma.Verify(dll, keyID, signMessage, signatureStr)
				if !success {
					return fmt.Errorf("RSA verification failed")
				}
				if !verified {
					return fmt.Errorf("RSA verification returned false")
				}
				return err
			})
			results = append(results, result)

			if result.Success {
				fmt.Printf("  %s: %.2f ms avg\n", result.DataSize, result.AvgTimeMs)
			} else {
				fmt.Printf("  %s: FAILED\n", result.DataSize)
			}
		}
	}

	// Generate and save results table
	fmt.Printf("\n=== COMPLETE BENCHMARK RESULTS ===\n")
	fmt.Printf("%-20s %-12s %-15s %-15s %-10s\n", "Operation", "Data Size", "Total Time (s)", "Avg Time (ms)", "Status")
	fmt.Printf("%-20s %-12s %-15s %-15s %-10s\n", "--------------------", "------------", "---------------", "---------------", "----------")

	var output string
	output += "=== COMPREHENSIVE CRYPTOGRAPHIC BENCHMARK RESULTS ===\n"
	output += fmt.Sprintf("Test runs: %d iterations per test\n", runs)
	output += fmt.Sprintf("Test date: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	output += fmt.Sprintf("%-20s %-12s %-15s %-15s %-10s\n", "Operation", "Data Size", "Total Time (s)", "Avg Time (ms)", "Status")
	output += "--------------------" + " " + "------------" + " " + "---------------" + " " + "---------------" + " " + "----------" + "\n"

	for _, result := range results {
		status := "SUCCESS"
		if !result.Success {
			status = "FAILED"
		}

		totalTimeSeconds := result.TotalTime.Seconds()

		fmt.Printf("%-20s %-12s %-15.3f %-15.3f %-10s\n",
			result.Operation, result.DataSize, totalTimeSeconds, result.AvgTimeMs, status)

		output += fmt.Sprintf("%-20s %-12s %-15.3f %-15.3f %-10s\n",
			result.Operation, result.DataSize, totalTimeSeconds, result.AvgTimeMs, status)
	}

	// Save results to file
	filename := fmt.Sprintf("benchmark_results_%s.txt", time.Now().Format("20060102_150405"))
	err = os.WriteFile(filename, []byte(output), 0644)
	if err != nil {
		t.Errorf("Failed to save results to file: %v", err)
	} else {
		fmt.Printf("\nResults saved to: %s\n", filename)
	}

	// Cleanup - delete the test keys
	enigma.DeleteKey(dll, keyID)
	enigma.DeleteKey(dll, encKeyID)
}
