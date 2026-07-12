package main

import (
	"log"
	"os"

	"github.com/lb2114/per-proc-route/internal/cgroup"
	"github.com/lb2114/per-proc-route/internal/daemon"
	"github.com/lb2114/per-proc-route/internal/ebpf"
	"github.com/lb2114/per-proc-route/internal/routing"
)

func main() {
	var procsPaths []string
	var err error
	args := os.Args

	if len(args) != 3 || (len(args) > 1 && args[1] != "--config") {
		log.Fatalf("Invalid arguments\n Use 'pprd --config [path to config file]' to run ")
	}
	procsPaths, err = daemon.ParseConfig(args[2])
	if err != nil {
		log.Fatalf("Fail to read config file %s: %v", args[1], err)
	}

	if err = routing.InitRouting(); err != nil {
		log.Fatal("Fail to setup routing tables and policy rules: ", err)
	}

	if err = cgroup.InitCgroup(); err != nil {
		log.Fatal("Fail to setup cgroup: ", err)
	}

	objs, lnks, err := ebpf.InitEBPF(procsPaths)
	if err != nil {
		log.Fatal("Fail to load eBPF: ", err)
	}
	defer objs.Close()
	defer lnks.Close()

	l, err := daemon.CreateListener()
	if err != nil {
		log.Fatal("Fail to create unix socket: ", err)
	}
	defer l.Close()

	logCh := make(chan error, 256)
	defer close(logCh)

	go func() {
		for {
			err, ok := <-logCh
			if !ok {
				return
			}
			log.Println(err)
		}
	}()

	go ebpf.UserspaceEBPF(objs, logCh)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Fail to accept connection: ", err)
			os.Exit(1)
		}
		go daemon.HandleConnection(conn, logCh)
	}
}
