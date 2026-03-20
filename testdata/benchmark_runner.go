package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	VexilBin    = "../vexil"
	ReposFile   = "benchmark_repos.json"
	ResultsFile = "benchmark_results.jsonl"
	TempDir     = "./temp_repos"
	MaxWorkers  = 4
)

type Repo struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Category string `json:"category"`
}

type FindingDetail struct {
	Type string `json:"type"`
	File string `json:"file"`
}

type VexilOutput struct {
	Findings []struct {
		SecretType string `json:"secret_type"`
		FilePath   string `json:"file_path"`
	} `json:"findings"`
	ScanMetadata struct {
		WorstConfidence string `json:"worst_confidence"`
	} `json:"scan_metadata"`
}

type Result struct {
	Name            string          `json:"name"`
	Category        string          `json:"category"`
	Duration        float64         `json:"duration"`
	Findings        int             `json:"findings"`
	WorstConfidence string          `json:"worst_confidence"`
	FindingTypes    []string        `json:"finding_types"`
	FindingDetails  []FindingDetail `json:"finding_details"`
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
}

func getExistingResults() (map[string]bool, error) {
	existing := make(map[string]bool)
	file, err := os.Open(ResultsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return existing, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		var minimal struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &minimal); err == nil && minimal.Name != "" {
			existing[minimal.Name] = true
		}
	}
	return existing, scanner.Err()
}

func scanRepo(ctx context.Context, repo Repo) Result {
	repoDirName := strings.ReplaceAll(repo.Name, "/", "_")
	targetDir := filepath.Join(TempDir, repoDirName)
	absTargetDir, _ := filepath.Abs(targetDir)
	
	res := Result{
		Name:     repo.Name,
		Category: repo.Category,
		Status:   "error",
	}

	// Cleanup on end
	defer os.RemoveAll(targetDir)

	// 1. Clone
	cloneCtx, cancelCleanup := context.WithTimeout(ctx, 5*time.Minute)
	defer cancelCleanup()
	
	fmt.Printf("[%s] Cloning...\n", repo.Name)
	cmdClone := exec.CommandContext(cloneCtx, "git", "clone", "--depth", "1", repo.URL, targetDir)
	if out, err := cmdClone.CombinedOutput(); err != nil {
		res.Error = fmt.Sprintf("clone error: %v (output: %s)", err, string(out))
		return res
	}

	// 2. Scan
	absVexil, _ := filepath.Abs(VexilBin)
	fmt.Printf("[%s] Scanning...\n", repo.Name)
	startTime := time.Now()
	
	cmdScan := exec.CommandContext(ctx, absVexil, "-format", "json")
	cmdScan.Dir = absTargetDir
	output, err := cmdScan.Output()
	res.Duration = time.Since(startTime).Seconds()

	// Vexil might return exit code 1 or 2 if findings are found, so we check output existence
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			res.Error = fmt.Sprintf("scan execution error: %v", err)
			return res
		}
	}

	// 3. Parse result
	var vOut VexilOutput
	if err := json.Unmarshal(output, &vOut); err != nil {
		// If fail to parse but we have output, maybe it's just no findings or malformed
		// We'll mark as success with 0 findings if output was generated
		if len(output) > 0 {
			res.Error = fmt.Sprintf("json parse error: %v", err)
		} else {
			res.Status = "success"
			res.WorstConfidence = "None"
			return res
		}
	}

	res.Status = "success"
	res.Findings = len(vOut.Findings)
	res.WorstConfidence = vOut.ScanMetadata.WorstConfidence
	
	typeSet := make(map[string]bool)
	for _, f := range vOut.Findings {
		res.FindingDetails = append(res.FindingDetails, FindingDetail{
			Type: f.SecretType,
			File: f.FilePath,
		})
		typeSet[f.SecretType] = true
	}
	
	for t := range typeSet {
		res.FindingTypes = append(res.FindingTypes, t)
	}

	return res
}

func main() {
	if err := os.MkdirAll(TempDir, 0755); err != nil {
		log.Fatalf("Failed to create temp dir: %v", err)
	}

	// Load repos
	fileRepos, err := os.ReadFile(ReposFile)
	if err != nil {
		log.Fatalf("Failed to read repos file: %v", err)
	}
	var repos []Repo
	if err := json.Unmarshal(fileRepos, &repos); err != nil {
		log.Fatalf("Failed to unmarshal repos: %v", err)
	}

	// Get existing
	existing, err := getExistingResults()
	if err != nil {
		log.Printf("Warning: failed to read existing results: %v", err)
	}

	var toProcess []Repo
	for _, r := range repos {
		if !existing[r.Name] {
			toProcess = append(toProcess, r)
		}
	}

	fmt.Printf("Starting benchmark for %d repositories (%d already done)...\n", len(repos), len(existing))
	if len(toProcess) == 0 {
		fmt.Println("No repositories left to process.")
		return
	}

	// Results file
	fOut, err := os.OpenFile(ResultsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open results file: %v", err)
	}
	defer fOut.Close()

	// Worker Pool
	var wg sync.WaitGroup
	jobs := make(chan Repo, len(toProcess))
	results := make(chan Result, len(toProcess))

	// Start workers
	for w := 1; w <= MaxWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range jobs {
				results <- scanRepo(context.Background(), repo)
			}
		}()
	}

	// Send jobs
	for _, r := range toProcess {
		jobs <- r
	}
	close(jobs)

	// Result writer
	done := make(chan bool)
	go func() {
		for res := range results {
			data, _ := json.Marshal(res)
			fOut.Write(append(data, '\n'))
			fmt.Printf("[%s] Done. Findings: %d, Status: %s\n", res.Name, res.Findings, res.Status)
		}
		done <- true
	}()

	wg.Wait()
	close(results)
	<-done

	fmt.Println("Benchmark complete.")
}
