package main

import (
	"fmt"
	"log"
	"os"

	"github.com/lb2114/per-proc-route/internal/cli"
)

func main() {
	args := os.Args
	if len(args) < 3 {
		fmt.Println("Invalid command\nUsage: ppr run [cmd] [arguments]")
		os.Exit(0)
	}
	switch args[1] {
	case "run":
		if err := cli.Run(args[2:]); err != nil {
			log.Fatal(err)
			os.Exit(1)
		}
	default:
		fmt.Println("Invalid command\nUsage: ppr run [cmd] [arguments]")
		os.Exit(0)
	}
}
