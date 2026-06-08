package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/GildedPleb/blast-radius/internal/config"
)

// Use a single, reliably-detected secret everywhere we need candidates.
const testSecret = "AKIAIOSFODNN7EXAMPLESECRETKEY1234567890"

func TestRunClipboard(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		return exec.Command("true")
	}

	RunClipboard(nil)
	RunClipboard([]string{})
	RunClipboard([]string{"status"})
	RunClipboard([]string{"check"})
	RunClipboard([]string{"clear"})
	RunClipboard([]string{"unknown"})
}

func TestRunClipboard_CheckWithSecrets(t *testing.T) {
	defer resetTestOverrides(t)

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'export AWS_SECRET=%s\nnormal text'", testSecret))
		}
		return exec.Command("true")
	}

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "AUTH ") {
				continue
			}
			if strings.HasPrefix(line, "CHECK_HASH ") {
				_, _ = fmt.Fprintf(serverConn, "%s\n", `{"status":"ok","known":true}`)
			}
		}
	}()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	RunClipboard([]string{"check"})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, `"known":true`) {
		t.Errorf("expected known:true, got: %q", out)
	}
	if !strings.Contains(out, `"secrets_found":1`) {
		t.Errorf("expected secrets_found:1, got: %q", out)
	}
}

func TestRunClipboard_CheckNoCandidates(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", `printf "just normal text here\nno secrets"`)
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"check"})
}

func TestRunClipboard_PbpasteFails(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("false")
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"check"})
	RunClipboard([]string{"status"})
}

func TestRunClipboard_Scrub_PbpasteFails(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("false")
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"scrub"})
	RunClipboard([]string{"redact"})
}

func TestRunClipboard_CheckDaemonNotRunning(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Good long secret so ExtractCandidates actually returns something
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'AWS_SECRET=%s\n'", testSecret))
		}
		return exec.Command("true")
	}

	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errForTest
	}

	RunClipboard([]string{"check"})
	// This now reaches the "daemon not running" branch in the check path
}

func TestRunClipboard_Clear(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbcopy" || strings.HasSuffix(name, "/pbcopy") {
			return exec.Command("true")
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"clear"})
}

func TestRunClipboard_Unknown(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	RunClipboard([]string{"foo"})
	RunClipboard([]string{"bar", "baz"})
}

func TestRunClipboard_CheckFullConnPath(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", `printf "DB_PASSWORD=supersecret123\nAPI_KEY=anothersecret456\nNORMAL=line\n"`)
		}
		return exec.Command("true")
	}

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		for i := 0; i < 5; i++ {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "AUTH ") {
				continue
			}
			if strings.HasPrefix(line, "CHECK_HASH ") {
				resp := `{"status":"ok","known":false}`
				if i%2 == 0 {
					resp = `{"status":"ok","known":true}`
				}
				_, _ = fmt.Fprintf(serverConn, "%s\n", resp)
			}
		}
	}()

	RunClipboard([]string{"check"})
}

func TestRunClipboard_CheckWithCandidatesButAuthSkipped(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", `printf "DB_PASS=sekret\n"`)
		}
		return exec.Command("true")
	}

	bad := t.TempDir() + "/nosibling.sock"
	config.SocketPathFn = func() string { return bad }

	client, server := net.Pipe()
	netDialTimeout = func(n, a string, d time.Duration) (net.Conn, error) { return client, nil }

	go func() {
		defer server.Close()
		r := bufio.NewReader(server)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = server.Write([]byte(`{"status":"ok","known":false}` + "\n"))
		}
	}()

	RunClipboard([]string{"check"})
}

func TestRunClipboard_Scrub(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	planted1 := testSecret
	planted2 := "ghp_1234567890abcdefABCDEF1234567890abcdef"
	nonSecret := "NORMAL=line"

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "AUTH ") {
				continue
			}
			if strings.HasPrefix(line, "CHECK_HASH ") {
				_, _ = fmt.Fprintf(serverConn, "%s\n", `{"status":"ok","known":true}`)
			}
		}
	}()

	var capturedStdin bytes.Buffer

	pbpasteCmd := func() *exec.Cmd {
		return exec.Command("sh", "-c", fmt.Sprintf("printf 'DB_PASSWORD=%s\nAPI_TOKEN=%s\n%s\n'", planted1, planted2, nonSecret))
	}

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return pbpasteCmd()
		}
		if name == "pbcopy" || strings.HasSuffix(name, "/pbcopy") {
			cmd := exec.Command("sh", "-c", "cat")
			cmd.Stdout = &capturedStdin
			return cmd
		}
		return exec.Command("true")
	}

	origConfigLoad := configLoad
	configLoad = func() (*config.Config, string, error) {
		c := &config.Config{}
		c.Pillar5.RedactPlaceholder = "[REDACTED-TEST]"
		return c, "/tmp/fake.yaml", nil
	}
	defer func() { configLoad = origConfigLoad }()

	RunClipboard([]string{"scrub"})

	written := capturedStdin.String()
	if !strings.Contains(written, "[REDACTED-TEST]") {
		t.Errorf("scrub did not redact with expected placeholder; got: %q", written)
	}
	if strings.Contains(written, planted1) || strings.Contains(written, planted2) {
		t.Errorf("scrub left secret values in output: %q", written)
	}
	if !strings.Contains(written, nonSecret) {
		t.Errorf("scrub should have preserved non-secret content: %q", written)
	}

	RunClipboard([]string{"redact"})
}

func TestRunClipboard_CheckCandidatesButNoneKnown(t *testing.T) {
	defer resetTestOverrides(t)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'export AWS_SECRET=%s\n'", testSecret))
		}
		return exec.Command("true")
	}

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	go func() {
		defer serverConn.Close()
		rd := bufio.NewReader(serverConn)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "CHECK_HASH ") {
				_, _ = fmt.Fprintf(serverConn, "%s\n", `{"status":"ok","known":false}`)
			}
		}
	}()

	RunClipboard([]string{"check"})

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, `"known":false`) {
		t.Errorf("expected known:false, got: %q", out)
	}
	if !strings.Contains(out, `"secrets_found":0`) {
		t.Errorf("expected secrets_found:0, got: %q", out)
	}
}

func TestRunClipboard_Clear_PbcopyFails(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbcopy" || strings.HasSuffix(name, "/pbcopy") {
			return exec.Command("false")
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"clear"})
	RunClipboard([]string{"nuke"})
}

func TestRunClipboard_Scrub_DaemonNotRunning(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	// Good secret so we actually reach batchCheckKnownSecrets
	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'DB_PASS=%s\n'", testSecret))
		}
		return exec.Command("true")
	}

	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errForTest
	}

	RunClipboard([]string{"scrub"})
	RunClipboard([]string{"redact"})
	// This now reaches the "daemon not running" branch in the scrub path
}

// === MERGED TEST ===
// This single test replaces the previous near-duplicate
// TestRunClipboard_Scrub_PbcopyFails + TestRunClipboard_Scrub_PbcopyFailAfterRedact.
// It exercises: candidates found → batchCheck succeeds with known secrets
// → redact happens → pbcopy Run() fails → the exact error branch you wanted covered.
func TestRunClipboard_Scrub_PbcopyFailsAfterRedact(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'DB_PASS=%s\n'", testSecret))
		}
		if name == "pbcopy" || strings.HasSuffix(name, "/pbcopy") {
			return exec.Command("false") // force Run() error after redact
		}
		return exec.Command("true")
	}

	go func() {
		defer serverConn.Close()
		r := bufio.NewReader(serverConn)
		for {
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
			_, _ = serverConn.Write([]byte(`{"status":"ok","known":true}` + "\n"))
		}
	}()

	RunClipboard([]string{"scrub"})
	// Also exercises the "redact" alias
	RunClipboard([]string{"redact"})
}

func TestRunClipboard_Scrub_NoCandidates(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", `printf "just normal text here\nno secrets"`)
		}
		return exec.Command("true")
	}

	RunClipboard([]string{"scrub"})
	RunClipboard([]string{"redact"})
}

func TestRunClipboard_Scrub_CandidatesButNoneKnown(t *testing.T) {
	defer resetTestOverrides(t)
	restore := silenceOutput()
	defer restore()

	execCommand = func(name string, arg ...string) *exec.Cmd {
		if name == "pbpaste" || strings.HasSuffix(name, "/pbpaste") {
			return exec.Command("sh", "-c", fmt.Sprintf("printf 'SECRET=%s\n'", testSecret))
		}
		return exec.Command("true")
	}

	clientConn, serverConn := net.Pipe()
	netDialTimeout = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return clientConn, nil
	}

	go func() {
		defer serverConn.Close()
		rd := bufio.NewReader(serverConn)
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.TrimSpace(line), "CHECK_HASH ") {
				_, _ = fmt.Fprintf(serverConn, "%s\n", `{"status":"ok","known":false}`)
			}
		}
	}()

	RunClipboard([]string{"scrub"})
}
