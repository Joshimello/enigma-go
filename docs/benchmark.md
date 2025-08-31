# Benchmark Documentation

This document provides performance benchmarking information for the Enigma-Go cryptographic operations.

## Running Benchmarks

### Running with Go

You can run the benchmark tests directly using Go:

```bash
cd tests
go test -bench=. -benchmem
```

### Building and Running Benchmark Executable

To build a standalone benchmark executable:

```bash
cd tests
go build -o benchmark.exe benchmark_test.go shared.go
```

Then run:

```bash
./benchmark.exe
```

## Test Environment

The benchmark results below were collected on the following system:

- **CPU**: Apple M4 Pro 14-core
- **RAM**: 24GB 6400 MHz
- **Storage**: 1TB SSD (6000 MB/s read/write)
- **OS**: macOS (via Parallels)
- **Go Version**: 1.24.1

## Benchmark Results

### AES Encryption/Decryption Performance

The following results are from 100 iterations per test:

| Operation      | Data Size | Total Time (s) | Avg Time (ms) | Status  |
| -------------- | --------- | -------------- | ------------- | ------- |
| AES Stream Enc | 10 B      | 0.048          | 0.483         | SUCCESS |
| AES Stream Enc | 500 B     | 0.041          | 0.414         | SUCCESS |
| AES Stream Enc | 1 KB      | 0.050          | 0.501         | SUCCESS |
| AES Stream Enc | 5 KB      | 0.049          | 0.493         | SUCCESS |
| AES Stream Enc | 10 KB     | 0.056          | 0.561         | SUCCESS |
| AES Stream Enc | 100 KB    | 0.373          | 3.732         | SUCCESS |
| AES Stream Enc | 1 MB      | 3.535          | 35.354        | SUCCESS |
| AES Stream Dec | 10 B      | 0.052          | 0.519         | SUCCESS |
| AES Stream Dec | 500 B     | 0.051          | 0.514         | SUCCESS |
| AES Stream Dec | 1 KB      | 0.048          | 0.478         | SUCCESS |
| AES Stream Dec | 5 KB      | 0.055          | 0.548         | SUCCESS |
| AES Stream Dec | 10 KB     | 0.053          | 0.533         | SUCCESS |
| AES Stream Dec | 100 KB    | 0.421          | 4.208         | SUCCESS |
| AES Stream Dec | 1 MB      | 3.627          | 36.274        | SUCCESS |

### RSA Encryption/Decryption Performance

The following results are from 10 iterations per test:

| Operation  | Data Size | Total Time (s) | Avg Time (ms) | Status  |
| ---------- | --------- | -------------- | ------------- | ------- |
| RSA Enc    | 10 B      | 1.559          | 155.885       | SUCCESS |
| RSA Enc    | 500 B     | 0.115          | 11.466        | SUCCESS |
| RSA Enc    | 1 KB      | 0.118          | 11.783        | SUCCESS |
| RSA Enc    | 5 KB      | 1.557          | 155.657       | SUCCESS |
| RSA Enc    | 10 KB     | 1.552          | 155.156       | SUCCESS |
| RSA Enc    | 100 KB    | 1.560          | 156.001       | SUCCESS |
| RSA Enc    | 1 MB      | 1.580          | 158.032       | SUCCESS |
| RSA Dec    | 10 B      | 4.997          | 499.742       | SUCCESS |
| RSA Dec    | 500 B     | 5.005          | 500.522       | SUCCESS |
| RSA Dec    | 1 KB      | 5.005          | 500.463       | SUCCESS |
| RSA Dec    | 5 KB      | 5.019          | 501.871       | SUCCESS |
| RSA Dec    | 10 KB     | 5.015          | 501.484       | SUCCESS |
| RSA Dec    | 100 KB    | 5.003          | 500.332       | SUCCESS |
| RSA Dec    | 1 MB      | 5.008          | 500.830       | SUCCESS |
| RSA Sign   | 190 B     | 5.018          | 501.837       | SUCCESS |
| RSA Verify | 190 B     | 1.557          | 155.657       | SUCCESS |

## Custom Benchmark Configuration

To run custom benchmarks with different parameters:

```bash
# Run specific benchmark functions
go test -bench=BenchmarkAES -benchtime=30s

# Run with custom iteration count
go test -bench=BenchmarkRSA -count=5

# Generate detailed profiling data
go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
```

## Benchmark Test Files

The benchmark implementation can be found in:

- `tests/aes_benchmark_test.go` - AES performance tests
- `tests/rsa_benchmark_test.go` - RSA performance tests
- `tests/benchmark_test.go` - Combined benchmark suite
- `tests/shared.go` - Common test utilities

Results are automatically saved with timestamps in the format:

- `tests/aes_benchmark_results_YYYYMMDD_HHMMSS.txt`
- `tests/rsa_benchmark_results_YYYYMMDD_HHMMSS.txt`
