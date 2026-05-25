package cli

import (
	"encoding/json"
	"fmt"
)

// RunConfig handles subcommands under "blastradius config".
func RunConfig(args []string) {
	cfg, _, err := configLoad()
	if err != nil {
		fmt.Printf(`{"error":"%s"}`+"\n", err)
		return
	}
	if len(args) == 0 {
		fmt.Println("config redaction")
		return
	}
	switch args[0] {
	case "redaction":
		jsonOut, _ := json.Marshal(cfg.Redaction)
		fmt.Println(string(jsonOut))
	default:
		fmt.Println("unknown config subcommand")
	}
}
