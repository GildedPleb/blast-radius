package handlers

type RescanHandler struct{}

func (RescanHandler) Name() string { return "RESCAN" }

func (RescanHandler) Handle(_ string, d DaemonContext) (any, error) {
	if err := d.TriggerPillar1Rescan(); err != nil {
		return map[string]any{
			"status":  "error",
			"message": err.Error(),
		}, nil
	}

	resp := d.Pillar1ScanStatus()
	resp["status"] = "ok"

	// Include rich per-collector results if available
	if res := d.LastPillar1Rescan(); res != nil {
		resp["collector_results"] = res.CollectorResults
		if len(res.Errors) > 0 {
			resp["errors"] = res.Errors
		}
	}

	return resp, nil
}
