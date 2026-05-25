package handlers

type HaltHandler struct{}

func (HaltHandler) Name() string { return "HALT" }

func (HaltHandler) Handle(_ string, d DaemonContext) (any, error) {
	d.TriggerShutdown()
	return map[string]string{
		"status":  "ok",
		"message": "Shutting down daemon...",
	}, nil
}
