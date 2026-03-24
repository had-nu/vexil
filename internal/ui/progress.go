// Copyright (c) 2026 André Ataíde. All rights reserved. Vexil Signature: ead76f22a4a059769cc1212fb9dcc88e9fa7ea38bd4747b9f1a722e957e2ffe8
package ui

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/had-nu/vexil/v2/internal/types"
)

type DockerProgress struct {
	w         io.Writer
	phase     string
	total     int
	current   int
	startTime time.Time
}

func NewProgressReporter(w io.Writer) *DockerProgress {
	return &DockerProgress{w: w}
}

func (p *DockerProgress) StartPhase(name string, total int) {
	p.phase = name
	p.total = total
	p.current = 0
	p.startTime = time.Now()
	// Clear line and print start
	fmt.Fprintf(p.w, "%s %s[%s]%s %sStarting %s...%s\n", 
		cyan, reset, time.Now().Format("15:04:05.000"), cyan, dim, name, reset)
}

func (p *DockerProgress) Update(current int) {
	p.current = current
	p.render()
}

func (p *DockerProgress) EndPhase() {
	p.render()
	fmt.Fprint(p.w, "\n")
}

func (p *DockerProgress) render() {
	percent := 0.0
	if p.total > 0 {
		percent = float64(p.current) / float64(p.total) * 100
	}

	elapsed := time.Since(p.startTime).Truncate(time.Second)
	
	// Progress bar
	width := 20
	completed := int(float64(width) * (percent / 100))
	if completed > width {
		completed = width
	}
	bar := strings.Repeat("=", completed)
	if completed < width {
		bar += ">" + strings.Repeat(" ", width-completed-1)
	}
	
	// Docker-like status line
	// \r to return to start of line, \033[K to clear to end of line
	fmt.Fprintf(p.w, "\r %s[%02d:%02d]%s [%s] %3.0f%% (%d/%d) %s%-15s%s\033[K",
		cyan, int(elapsed.Minutes()), int(elapsed.Seconds())%60, reset,
		bar, percent, p.current, p.total,
		dim, p.phase, reset)
}

func PrintProjectSummary(w io.Writer, root string, findings []types.Finding) {
	if len(findings) == 0 {
		return
	}

	projectCounts := make(map[string]int)
	for _, f := range findings {
		// Identify project as the first component of the relative path
		rel, err := filepath.Rel(root, f.FilePath)
		if err != nil {
			rel = f.FilePath
		}
		
		path := filepath.ToSlash(rel)
		parts := strings.Split(path, "/")
		
		project := "."
		if len(parts) > 1 {
			project = parts[0]
			// In case it's specifically "./" prefix (unlikely with filepath.Rel)
			if project == "." {
				project = parts[1]
			}
		} else if len(parts) == 1 && parts[0] != "." && parts[0] != "" {
			// It's a file in the root, but let's label it as 'root' or '.'
			project = "."
		}

		projectCounts[project]++
	}

	var projects []string
	for k := range projectCounts {
		projects = append(projects, k)
	}
	sort.Strings(projects)

	fmt.Fprintln(w, "\n"+green+"--- Project/Module Summary ---"+reset)
	header := fmt.Sprintf("%-35s | %s", "Location", "Findings")
	fmt.Fprintln(w, header)
	fmt.Fprintln(w, strings.Repeat("-", len(header)))

	for _, p := range projects {
		fmt.Fprintf(w, "%s%-35s%s | %d\n", white, p, reset, projectCounts[p])
	}
	fmt.Fprintln(w)
}
