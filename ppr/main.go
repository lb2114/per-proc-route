package main

import (
	"fmt"
	"log"
	"os"

	"github.com/lb2114/per-proc-route/internal/ebpf"
	"github.com/lb2114/per-proc-route/internal/routing"
	"github.com/lb2114/per-proc-route/internal/tools"
)

const usage = `Usage:
  ppr start <procs> <config>  Configure routing and load eBPF programs
  ppr update <procs>          Update the process path list
  ppr help                    Show this help
`

func main() {
	args := os.Args
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch args[1] {
	case "help":
		if len(args) != 2 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		fmt.Print(usage)
	case "start":
		if len(args) != 4 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		procsPaths, err := tools.ParseList(args[2])
		if err != nil {
			log.Fatalf("Cannot load process list %q: %v", args[2], err)
		}
		userConfig, err := tools.ParseConfig(args[3])
		if err != nil {
			log.Fatalf("Cannot load configuration %q: %v", args[3], err)
		}
		if err := routing.InitRouting(userConfig); err != nil {
			log.Fatal("Failed to configure routing: ", err)
		}
		if err := ebpf.InitEBPF(procsPaths); err != nil {
			log.Fatal("Failed to initialize eBPF programs and links: ", err)
		}
	case "update":
		if len(args) != 3 {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		procsPaths, err := tools.ParseList(args[2])
		if err != nil {
			log.Fatalf("Cannot load process list %q: %v", args[2], err)
		}
		if err := ebpf.ReloadProcsMap(procsPaths); err != nil {
			log.Fatal("Failed to update process path list: ", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n", args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}
