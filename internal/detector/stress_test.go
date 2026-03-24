// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: e4db61b0928dd0ad3d365f07a64728d40c29f38cac94e485c4a9acc143662094
package detector

import (
	"fmt"
	"testing"
)

// BenchmarkDetectLargeFile measures performance when scanning a large content block with many findings.
func BenchmarkDetectLargeFile(b *testing.B) {
	d := New(nil)
	// Create a 1MB buffer with a secret pattern every few lines
	var content []byte
	for i := 0; i < 10000; i++ {
		content = append(content, []byte(fmt.Sprintf("line %d: some random text\n", i))...)
		if i%10 == 0 {
			content = append(content, []byte(fmt.Sprintf("api_key: \"ak_%d_1234567890abcdef1234567890abcdef\"\n", i))...)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(content)
	}
}

func TestDetector_StressManyPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}

	d := New(nil)
	// 100k lines, 10k findings
	largeContent := make([]byte, 0, 5*1024*1024)
	for i := 0; i < 100000; i++ {
		if i%10 == 0 {
			largeContent = append(largeContent, []byte(fmt.Sprintf("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY%010d\n", i))...)
		} else {
			largeContent = append(largeContent, []byte("nothing to see here, just a normal line of code\n")...)
		}
	}

	findings, err := d.Detect(largeContent)
	if err != nil {
		t.Fatalf("Stress test failed: %v", err)
	}

	if len(findings) != 10000 {
		t.Errorf("Expected 10000 findings, got %d", len(findings))
	}
}
