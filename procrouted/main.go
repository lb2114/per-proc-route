package main

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Proc struct {
	name string
	pid  int64
}

var DIR_PROCS []Proc

func setupCgroup() error {
	err := os.MkdirAll("/sys/fs/cgroup/ppr/direct", 0755)
	if err != nil {
		return err
	}
	fs, err := os.OpenFile("/sys/fs/cgroup/ppr/direct/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer fs.Close()

	for _, proc := range DIR_PROCS {
		fmt.Fprintf(fs, "%d\n", proc.pid)
	}

	return nil
}

func loadEBPF() (*markerObjects, link.Link, error) {
	var objs markerObjects
	if err := loadMarkerObjects(&objs, nil); err != nil {
		return nil, nil, err
	}

	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/ppr/direct",
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.markerPrograms.MarkSocket,
	})
	if err != nil {
		return nil, nil, err
	}

	return &objs, lnk, nil
}

func main() {
	err := setupCgroup()
	if err != nil {
		log.Fatal("Fail to setup cgroup:", err)
		os.Exit(1)
	}

	objs, link, err := loadEBPF()
	if err != nil {
		log.Fatal("Fail to load eBPF:", err)
		os.Exit(1)
	}
	defer objs.Close()
	defer link.Close()

	//загрузка eBPF кода

	// Добавление правила в routing tables (проверка на то, есть ли оно)

	// Функции добавить процесс по pid, по имени, удалить по pid и по имени, вывести список (сначала будет in memory хранилище)

	// Создание unix сокета, механизм ожидания команд от cli клиента (через poll мб)
}
