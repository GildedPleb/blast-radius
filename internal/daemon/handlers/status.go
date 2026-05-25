package handlers

type StatusHandler struct{}

func (StatusHandler) Name() string { return "STATUS" }

func (StatusHandler) Handle(_ string, d DaemonContext) (any, error) {
	return map[string]any{
		"status":   "ok",
		"message":  "Blast Radius daemon is running",
		"registry": d.RegistrySnapshot(),
		"time":     d.Now().Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}
