package handlers

import "testing"

func TestAllHandlers_Name(t *testing.T) {
	cases := []struct {
		h    CommandHandler
		want string
	}{
		{CheckHashHandler{}, "CHECK_HASH"},
		{CrumbsHandler{}, "CRUMBS"},
		{DuplicatesHandler{}, "DUPLICATES"},
		{HaltHandler{}, "HALT"},
		{PingHandler{}, "PING"},
		{ScrubHistoryHandler{}, "SCRUB_HISTORY"},
		{StatusHandler{}, "STATUS"},
		{RescanHandler{}, "RESCAN"},
		{UnknownHandler{}, ""},
	}

	for _, c := range cases {
		if got := c.h.Name(); got != c.want {
			t.Errorf("%T.Name() = %q, want %q", c.h, got, c.want)
		}
	}
}

func TestGetHandler(t *testing.T) {
	orig := commandHandlers
	defer func() { commandHandlers = orig }()

	// empty map: unknown and STOP-without-HALT both return UnknownHandler
	commandHandlers = map[string]CommandHandler{}
	h := GetHandler("PING")
	if _, ok := h.(UnknownHandler); !ok {
		t.Errorf("GetHandler(unknown) on empty = %T, want UnknownHandler", h)
	}
	h = GetHandler("STOP")
	if _, ok := h.(UnknownHandler); !ok {
		t.Errorf("GetHandler(STOP) with no HALT = %T, want UnknownHandler", h)
	}
	h = GetHandler("")
	if _, ok := h.(UnknownHandler); !ok {
		t.Errorf("GetHandler('') = %T, want UnknownHandler", h)
	}

	// populate a few (simulating what init()s do)
	commandHandlers["HALT"] = HaltHandler{}
	commandHandlers["PING"] = PingHandler{}
	commandHandlers["STATUS"] = StatusHandler{}

	h = GetHandler("PING")
	if _, ok := h.(PingHandler); !ok {
		t.Errorf("GetHandler(PING) = %T, want PingHandler", h)
	}
	h = GetHandler("HALT")
	if _, ok := h.(HaltHandler); !ok {
		t.Errorf("GetHandler(HALT) = %T, want HaltHandler", h)
	}
	h = GetHandler("STOP")
	if _, ok := h.(HaltHandler); !ok {
		t.Errorf("GetHandler(STOP) fallback = %T, want HaltHandler", h)
	}
	h = GetHandler("STATUS")
	if _, ok := h.(StatusHandler); !ok {
		t.Errorf("GetHandler(STATUS) = %T, want StatusHandler", h)
	}

	// still unknown for unregistered
	h = GetHandler("FOO")
	if _, ok := h.(UnknownHandler); !ok {
		t.Errorf("GetHandler(FOO) = %T, want UnknownHandler", h)
	}

	// UnknownHandler carries the original cmd token (not the args tail) so the
	// error message is useful. This exercises the nit fix + wire-visible behavior.
	h = GetHandler("FOOBAR")
	if u, ok := h.(UnknownHandler); ok {
		if u.cmd != "FOOBAR" {
			t.Errorf("GetHandler(FOOBAR) produced UnknownHandler with cmd=%q, want FOOBAR", u.cmd)
		}
		resp, err := h.Handle("tail args here", nil) // d may be nil; unknown ignores it
		if err != nil {
			t.Errorf("UnknownHandler.Handle returned err: %v", err)
		}
		m, _ := resp.(map[string]string)
		if got := m["message"]; got != "unknown command: FOOBAR" {
			t.Errorf("UnknownHandler message = %q, want %q", got, "unknown command: FOOBAR")
		}
	} else {
		t.Error("GetHandler(FOOBAR) did not return UnknownHandler")
	}
}

func TestRegister(t *testing.T) {
	orig := commandHandlers
	defer func() { commandHandlers = orig }()

	commandHandlers = map[string]CommandHandler{}

	// nil does nothing
	Register(nil)
	if len(commandHandlers) != 0 {
		t.Error("Register(nil) should not add anything")
	}

	// empty name does nothing (e.g. UnknownHandler)
	Register(UnknownHandler{})
	if len(commandHandlers) != 0 {
		t.Error("Register with empty Name() should not add anything")
	}

	// valid registration
	Register(PingHandler{})
	if _, ok := commandHandlers["PING"]; !ok {
		t.Error("Register(PingHandler) should have registered it")
	}

	// duplicate overwrites (last one wins)
	Register(StatusHandler{})
	if h, ok := commandHandlers["STATUS"]; !ok {
		t.Error("expected STATUS")
	} else if _, ok := h.(StatusHandler); !ok {
		t.Errorf("overwritten with wrong type: %T", h)
	}
}
