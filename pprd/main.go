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
	if err := routing.InitRouting(); err != nil {
		log.Fatal("Fail to setup routing tables and policy rules: ", err)
		os.Exit(1)
	}

	if err := cgroup.InitCgroup(); err != nil {
		log.Fatal("Fail to setup cgroup: ", err)
		os.Exit(1)
	}

	objs, link, err := ebpf.LoadEBPF()
	if err != nil {
		log.Fatal("Fail to load eBPF: ", err)
		os.Exit(1)
	}
	defer objs.Close()
	defer link.Close()

	l, err := daemon.CreateListener()
	if err != nil {
		log.Fatal("Fail to create unix socket: ", err)
		os.Exit(1)
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

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal("Fail to accept connection: ", err)
			os.Exit(1)
		}
		go daemon.HandleConnection(conn, logCh)
	}
}
