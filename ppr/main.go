package main

import (
	"log"
	"os"

	"github.com/lb2114/per-proc-route/internal/tools"
	"github.com/lb2114/per-proc-route/internal/ebpf"
	"github.com/lb2114/per-proc-route/internal/routing"
)

func main() {
	var procsPaths []string
	var err error
	args := os.Args

	if len(args) != 3 {
		log.Fatalf("Invalid arguments\n Use 'pprd [path to file with procs paths] [path to config file]' to run ")
	}
	procsPaths, err = tools.ParseList(args[1])
	if err != nil {
		log.Fatalf("Fail to read file %s: %v", args[1], err)
	}

	userConfig, err := tools.ParseConfig(args[2])
	if err != nil {
		log.Fatalf("Fail to read config file %s: %v", args[2], err)
	}
	if err = routing.InitRouting(userConfig); err != nil {
		log.Fatal("Fail to setup routing tables and policy rules: ", err)
	}

	err = ebpf.InitEBPF(procsPaths)
	if err != nil {
		log.Fatal("Fail to load eBPF: ", err)
	}
}
