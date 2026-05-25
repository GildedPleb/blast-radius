package handlers

type PingHandler struct{}

func (PingHandler) Name() string { return "PING" }

func (PingHandler) Handle(_ string, _ DaemonContext) (any, error) {
	return map[string]string{"status": "pong"}, nil
}
