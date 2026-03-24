// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: 0a4419f508ea24bebd320c318862c455bf80ecbc29c80fd5585348b2439ce1e2
package reporter

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/had-nu/vexil/v2/internal/types"
)

// BenchmarkCrossReferenceScaling measures the performance of cross-referencing findings by hash.
func BenchmarkCrossReferenceScaling(b *testing.B) {
	// 50,000 findings with a high degree of reuse (50 unique secrets)
	findings := make([]types.Finding, 50000)
	for i := 0; i < 50000; i++ {
		findings[i] = types.Finding{
			FilePath:  fmt.Sprintf("file_%d.go", i),
			ValueHash: fmt.Sprintf("hash_%d", i%50),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = computeCrossReferences(findings)
	}
}

func TestReporter_StressLargeJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	// 10,000 unique findings
	findings := make([]types.Finding, 10000)
	for i := 0; i < 10000; i++ {
		findings[i] = types.Finding{
			FilePath:        fmt.Sprintf("path/to/file_%d.go", i),
			LineNumber:      i,
			SecretType:      "Generic Secret",
			RedactedValue:   "[REDACTED]",
			ValueHash:       fmt.Sprintf("hash_%d", i%100), // 100 unique hashes
			Confidence:      "High",
			ExposureContext: "application_code",
		}
	}

	result := types.ScanResult{
		FilesScanned: 5000,
		Findings:     findings,
	}

	var buf bytes.Buffer
	b := testing.Benchmark(func(pb *testing.B) {
		for i := 0; i < pb.N; i++ {
			buf.Reset()
			_ = reportJSON(&buf, result)
		}
	})

	t.Logf("JSON Generation for 10k findings: %v", b.T/time.Duration(b.N))
	if b.N == 0 {
		t.Error("Benchmark failed to run")
	}
}
