package recorder

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/GildedPleb/blast-radius/internal/logging"
)

func mightContainSecret(line string) bool {
	return (len(line) > 0 &&
		(bytes.Contains([]byte(line), []byte("aws_")) ||
			bytes.Contains([]byte(line), []byte("ghp_")) ||
			bytes.Contains([]byte(line), []byte("gho_")) ||
			bytes.Contains([]byte(line), []byte("Bearer")) ||
			bytes.Contains([]byte(line), []byte("token=")) ||
			bytes.Contains([]byte(line), []byte("secret=")) ||
			bytes.Contains([]byte(line), []byte("password=")) ||
			bytes.Contains([]byte(line), []byte("apikey")) ||
			bytes.Contains([]byte(line), []byte("="))))
}

// findSecretSpans locates secrets and returns their byte offsets + hashes.
// This is the one-time work done at flush time.
func findSecretSpans(line string) []SecretSpan {
	var spans []SecretSpan
	b := []byte(line)

	// Known prefixes
	prefixes := [][]byte{[]byte("aws_"), []byte("ghp_"), []byte("gho_"), []byte("Bearer")}
	for _, p := range prefixes {
		idx := bytes.Index(b, p)
		if idx >= 0 {
			end := idx
			for end < len(b) && b[end] != ' ' && b[end] != '\t' {
				end++
			}
			val := b[idx:end]
			h := sha256.Sum256(val)
			spans = append(spans, SecretSpan{Hash: fmt.Sprintf("%x", h[:]), Start: idx, Length: len(val)})
		}
	}

	// After '=' (simple heuristic)
	if eq := bytes.LastIndexByte(b, '='); eq >= 0 && eq+1 < len(b) {
		start := eq + 1
		end := start
		for end < len(b) && b[end] != ' ' && b[end] != '\t' && b[end] != '"' && b[end] != '\'' {
			end++
		}
		if end > start {
			val := b[start:end]
			if len(val) >= 8 {
				h := sha256.Sum256(val)
				spans = append(spans, SecretSpan{Hash: fmt.Sprintf("%x", h[:]), Start: start, Length: len(val)})
			}
		}
	}
	return spans
}

// applyRedaction takes a raw line and its pre-computed SecretSpans and
// produces the output according to the requested mode.
// When preserveColors is true, original ANSI sequences around the secret are kept.
func applyRedaction(raw []byte, spans []SecretSpan, mode, custom string, preserveColors bool) []byte {
	if len(spans) == 0 {
		return raw
	}
	if mode == "" {
		mode = "replace"
	}
	if custom == "" {
		custom = "[REDACTED]"
	}

	if mode == "remove_cmd" {
		return nil
	}

	result := make([]byte, 0, len(raw)+64)
	last := 0
	for _, sp := range spans {
		result = append(result, raw[last:sp.Start]...)
		if preserveColors {
			result = append(result, []byte(custom)...)
		} else {
			result = append(result, []byte("%F{yellow}")...)
			result = append(result, []byte(custom)...)
			result = append(result, []byte("%f")...)
		}
		last = sp.Start + sp.Length
	}
	result = append(result, raw[last:]...)
	return result
}

func (r *Recorder) handleReplayRedacted(w io.Writer, requestedRecent int, mode, custom string, preserveColors bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	logging.RecorderPrintln("handleReplayRedacted: starting redacted replay")

	// Compute effective N: never expose more raw than the current buffer allows,
	// and never more than available history. This upholds the invariant.
	effectiveN := requestedRecent
	buf := r.getCurrentBuffer()
	if effectiveN > buf {
		effectiveN = buf
	}
	if effectiveN > len(r.recent) {
		effectiveN = len(r.recent)
	}

	for i, win := range r.recent {
		ageFromEnd := len(r.recent) - 1 - i
		isWithinN := ageFromEnd < effectiveN
		hasRaw := len(win.Lines) > 0

		if isWithinN && hasRaw {
			// Keep last N (capped by buffer) fully original/raw.
			// remove_cmd and other redaction modes do not affect these recent windows.
			if win.Command != "" {
				w.Write(append([]byte(win.Command), '\n'))
			}
			for _, ln := range win.Lines {
				w.Write(append(append([]byte(nil), ln.Raw...), '\n'))
			}
			continue
		}

		// Older than effective N (or no raw left): emit redacted form.
		// remove_cmd applies here.
		if mode == "remove_cmd" && win.HasSecret {
			continue
		}

		if len(win.RedactedLines) > 0 {
			if win.RedactedCommand != "" {
				w.Write(append([]byte(win.RedactedCommand), '\n'))
			}
			for _, rl := range win.RedactedLines {
				w.Write(append([]byte(rl), '\n'))
			}
			continue
		}

		// Fallback for unsealed older windows (e.g. just after buffer change).
		if win.Command != "" {
			if len(findSecretSpans(win.Command)) > 0 {
				out := applyRedaction([]byte(win.Command), findSecretSpans(win.Command), mode, custom, preserveColors)
				if out != nil {
					w.Write(append(out, '\n'))
				}
			} else {
				w.Write(append([]byte(win.Command), '\n'))
			}
		}
		for _, ln := range win.Lines {
			if len(ln.Secrets) == 0 {
				w.Write(append(append([]byte(nil), ln.Raw...), '\n'))
				continue
			}
			out := applyRedaction(ln.Raw, ln.Secrets, mode, custom, preserveColors)
			if out != nil {
				w.Write(append(out, '\n'))
			}
		}
	}
	w.Write([]byte("OK\n"))
	logging.RecorderPrintln("handleReplayRedacted: finished")
}
