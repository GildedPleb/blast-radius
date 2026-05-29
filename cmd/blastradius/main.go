package main

import (
	"os"

	"github.com/GildedPleb/blast-radius/internal/cli"
)

func main() {
	run(os.Args)
}

// run contains the actual entrypoint logic so it can be unit tested.
// It is intentionally unexported.
func run(args []string) {
	if len(args) < 2 || cli.IsHelp(args[1]) {
		cli.PrintHelp()
		return
	}
	cli.Run(args[1:])
}
