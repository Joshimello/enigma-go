//go:build windows

package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/joshimello/enigma-go/enigma"
)

// TestAESBenchmark tests AES encryption operations
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

	fmt.Printf("\n=== AES Cryptographic Benchmark ===\n")
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

	// Generate and save results table
	fmt.Printf("\n=== AES BENCHMARK RESULTS ===\n")
	fmt.Printf("%-20s %-12s %-15s %-15s %-10s\n", "Operation", "Data Size", "Total Time (s)", "Avg Time (ms)", "Status")
	fmt.Printf("%-20s %-12s %-15s %-15s %-10s\n", "--------------------", "------------", "---------------", "---------------", "----------")

	var output string
	output += "=== AES CRYPTOGRAPHIC BENCHMARK RESULTS ===\n"
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
	filename := fmt.Sprintf("aes_benchmark_results_%s.txt", time.Now().Format("20060102_150405"))
	err = os.WriteFile(filename, []byte(output), 0644)
	if err != nil {
		t.Errorf("Failed to save results to file: %v", err)
	} else {
		fmt.Printf("\nResults saved to: %s\n", filename)
	}
}
