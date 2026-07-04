package cgroup

import (
	"fmt"
	"os"

	"github.com/lb2114/per-proc-route/internal/config"
)

func InitCgroup() error {
	if err := os.MkdirAll(config.Cgroup, 0755); err != nil {
		return err
	}

	return nil
}

func AddPidToCGroup(pid int) error {
	fs, err := os.OpenFile(config.Cgroup+"/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer fs.Close()

	if _, err := fmt.Fprintf(fs, "%d\n", pid); err != nil {
		return fmt.Errorf("Can't add pid to cgroup: %w", err)
	}

	return nil
}
