package main

import (
	"log"
	"os"

	"github.com/lb2114/per-proc-route/internal/cgroup"
	"github.com/lb2114/per-proc-route/internal/ebpf"
	"github.com/lb2114/per-proc-route/internal/routing"
)

func main() {
	if err := routing.SetupRouting(); err != nil {
		log.Fatal("Fail to setup routing tables and policy rules:", err)
		os.Exit(1)
	}

	procs := make(map[int]bool)
	if err := cgroup.SetupCgroup(procs); err != nil {
		log.Fatal("Fail to setup cgroup:", err)
		os.Exit(1)
	}

	objs, link, err := ebpf.LoadEBPF()
	if err != nil {
		log.Fatal("Fail to load eBPF:", err)
		os.Exit(1)
	}
	defer objs.Close()
	defer link.Close()
}
