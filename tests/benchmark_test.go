//go:build windows

package main

import (
	"fmt"
	"math/rand"
	"time"
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
