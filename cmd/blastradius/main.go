package main

import (
	"os"

	"github.com/GildedPleb/blast-radius/internal/cli"
)

func main() {
	if len(os.Args) < 2 || cli.IsHelp(os.Args[1]) {
		cli.PrintHelp()
		return
	}
	cli.Run(os.Args[1:])
}
