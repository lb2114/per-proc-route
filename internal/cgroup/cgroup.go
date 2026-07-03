package cgroup

import (
	"fmt"
	"os"
)

type Proc struct {
	name string
	pid  int64
}

var DIR_PROCS []Proc

func SetupCgroup() error {
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
