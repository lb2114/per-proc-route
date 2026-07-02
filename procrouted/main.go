package main

import (
	"fmt"
	"os"
)

type Proc struct {
	name string
	pid  int64
}

var DIR_PROCS []Proc

func setupCgroup() error {
	err := os.MkdirAll("/sys/fs/cgroup/ppr/", 0755)
	if err != nil {
		return err
	}
	err = os.MkdirAll("/sys/fs/cgroup/ppr/direct", 0755)
	if err != nil {
		return err
	}
	fs, err := os.OpenFile("/sys/fs/cgroup/ppr/direct/cgroup.procs", os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	for _, proc := range DIR_PROCS {
		fmt.Fprintf(fs, "%d\n", proc.pid)
	}

	return nil
}

func main() {
	err := setupCgroup()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
