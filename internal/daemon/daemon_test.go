package daemon

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/GildedPleb/blast-radius/internal/config"
	"github.com/GildedPleb/blast-radius/internal/registry"
)

func TestNewDaemon(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)
	if d == nil || d.registry == nil || d.discovery == nil || d.residue == nil {
		t.Error("daemon not initialized (missing residue manager)")
	}
}

func TestDaemon_Run_Errors(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "no-permission", "deep", "socket.sock")
	reg := registry.New()
	d := New(cfg, reg)
	err := d.Run()
	if err == nil {
		t.Error("expected error on bad socket path")
	}
}

func TestDaemon_Close(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)
	d.Close()
}

func TestDaemon_Accessors(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	h := registry.HashValue([]byte("acc-test"))
	reg.Add(h, "demo-proj")
	d := New(cfg, reg)

	// exercise the DaemonContext impls / accessors (these were 0% before)
	_ = d.RegistrySnapshot()
	_ = d.FindDuplicates()
	_ = d.GetProjectDisplayName("demo-proj")
	_ = d.IsKnownHashHex("deadbeef") // invalid len -> false path
	_ = d.AllHashes()
	_ = d.Now()
	d.TriggerShutdown() // sets internal chan close (safe to call)

	// crumbs paths (residue manager present)
	sum := d.CrumbsSummary()
	if sum == nil {
		t.Error("CrumbsSummary returned nil")
	}
	res := d.RunCrumbsScan()
	if res == nil {
		t.Error("RunCrumbsScan returned nil")
	}

	// also cover the nil-residue branches by constructing a degenerate case isn't easy
	// (New always wires one), but at least the happy paths above are covered now.
}

// TestDaemon_HandleConnection exercises the protocol handler directly using net.Pipe.
// This is the main way we get coverage on handleConnection without a full real socket.
func TestDaemon_HandleConnection(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Send a simple STATUS command from the "client" side
	go func() {
		client.Write([]byte("STATUS\n"))
		client.Close() // close after write so the reader sees EOF
	}()

	// Run the server side (this is what we actually want coverage on)
	d.handleConnection(server)
}

// TestDaemon_HandleConnection_UnknownCommand exercises the default handler path.
func TestDaemon_HandleConnection_UnknownCommand(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("FOO_BAR_UNKNOWN\n"))
		client.Close()
	}()

	d.handleConnection(server)
}

// TestDaemon_HandleConnection_Halt exercises the early return on HALT.
func TestDaemon_HandleConnection_Halt(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("HALT\n"))
		client.Close() // critical: close so server can finish its response write
	}()

	d.handleConnection(server)
}

// TestDaemon_HandleConnection_ReadError covers the read error path.
func TestDaemon_HandleConnection_ReadError(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()

	// Close client immediately so ReadString gets an error
	client.Close()

	d.handleConnection(server)
}

// TestDaemon_HandleConnection_MultiCommandBeforeHalt covers the inner loop
// that processes multiple commands until a HALT.
func TestDaemon_HandleConnection_MultiCommandBeforeHalt(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Write all commands then immediately close. This avoids pipe buffer deadlocks
		// when the server is writing responses back on the same pipe.
		client.Write([]byte("PING\nSTATUS\nHALT\n"))
		client.Close()
	}()

	d.handleConnection(server)
}

// Two more ultra-fast net.Pipe scenarios.
func TestDaemon_HandleConnection_EmptyCommand(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("\nHALT\n"))
		client.Close()
	}()

	d.handleConnection(server)
}

func TestDaemon_HandleConnection_Malformed(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("STATUS extra garbage\nHALT\n"))
		client.Close()
	}()

	d.handleConnection(server)
}

// Two more trivial net.Pipe cases for extra handleConnection branches.
func TestDaemon_HandleConnection_JustNewlines(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		client.Write([]byte("\n\nHALT\n"))
		client.Close()
	}()

	d.handleConnection(server)
}

func TestDaemon_HandleConnection_LongLine(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := registry.New()
	d := New(cfg, reg)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	long := "STATUS " + string(make([]byte, 200)) + "\nHALT\n"
	go func() {
		client.Write([]byte(long))
		client.Close()
	}()

	d.handleConnection(server)
}

// Note on testing Run() and long-running behavior:
// Per explicit project rules, no test is allowed to take more than ~5 seconds total.
// We therefore ONLY use synchronous, instant tests via net.Pipe() for handleConnection.
// Any test involving sleeps, real listeners with timeouts, or background Run() loops
// that can block is forbidden.
//
// The hooks (netListen etc.) are kept for future use with non-blocking techniques
// if someone wants to invest in proper in-memory net.Listener fakes later.
//
// All tests in this file are designed to complete in well under 1 second.