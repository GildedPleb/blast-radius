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
