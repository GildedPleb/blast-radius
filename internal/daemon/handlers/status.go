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
		resp["pillar2"] = sum
	}
	// Pillar 1 scan status (manual rescan support)
	if p1 := d.Pillar1ScanStatus(); p1 != nil {
		if res := d.LastPillar1Rescan(); res != nil {
			p1["collector_results"] = res.CollectorResults
		}
		resp["pillar1"] = p1
	}
	return resp, nil
}
