package reporter

import (
	"fmt"
	"io"
	"time"
)

const (
	dim   = "\033[38;5;238m"
	cyan  = "\033[38;5;51m"
	green = "\033[38;5;46m"
	white = "\033[38;5;255m"
	reset = "\033[0m"
)

// colorizeHex provides a subtle transition from teal to cyber-blue
func colorizeHex(text string) string {
	var out string
	rs := []rune(text)
	for i, r := range rs {
		ratio := float64(i) / float64(len(rs))
		rVal := 0
		gVal := 150 + int(ratio*105)
		bVal := 200 + int((1-ratio)*55)
		out += fmt.Sprintf("\033[38;2;%d;%d;%dm%c", rVal, gVal, bVal, r)
	}
	return out + reset
}

func PrintBanner(w io.Writer) {
	now := time.Now().Format("15:04:05.000")
	tStamp := fmt.Sprintf("%s[%s]%s", cyan, now, reset)

	fmt.Fprintln(w)

	// Math / Crypto subtle background
	bg1 := colorizeHex("H(X) = -Σ P(x) log₂ P(x)")
	bg2 := colorizeHex("e = mc² ↣ E(k, m) = c")

	// Layout
	fmt.Fprintf(w, "%s    %s\n", tStamp, bg1)
	fmt.Fprintf(w, "              %sV E X I L%s\n", white, reset)
	fmt.Fprintf(w, "              %sEntropic Secret Detector%s      %s\n", dim, reset, bg2)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "    %s⊢%s %sENGINE%s  : %sONLINE%s\n", cyan, reset, white, reset, green, reset)
	fmt.Fprintf(w, "    %s⊢%s %sMATH%s    : Shannon Entropy Thresholds\n", cyan, reset, white, reset)
	fmt.Fprintf(w, "    %s⊢%s %sCRYPTO%s  : RSA, EC, AES-GCM, HMAC\n", cyan, reset, white, reset)
	fmt.Fprintf(w, "\n")
}
