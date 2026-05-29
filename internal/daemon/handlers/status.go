package handlers

type StatusHandler struct{}

func (StatusHandler) Name() string { return "STATUS" }

func (StatusHandler) Handle(_ string, d DaemonContext) (any, error) {
	resp := map[string]any{
		"status":   "ok",
		"message":  "Blast Radius daemon is running",
		"registry": d.RegistrySnapshot(),
		"time":     d.Now().Format("2006-01-02T15:04:05Z07:00"),
	}
	// Pillar 2 lightweight summary (always present when daemon up; count may be 0)
	if sum := d.CrumbsSummary(); sum != nil {
		resp["residue"] = sum
	}
	return resp, nil
}
