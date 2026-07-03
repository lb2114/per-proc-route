package cgroup

import (
	"fmt"
	"os"
)

func SetupCgroup(procs map[int]bool) error {
	if err := os.MkdirAll("/sys/fs/cgroup/ppr/direct", 0755); err != nil {
		return err
	}
	if err := os.MkdirAll("/sys/fs/cgroup/ppr/default", 0755); err != nil {
		return err
	}
	fs, err := os.OpenFile("/sys/fs/cgroup/ppr/direct/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer fs.Close()

	for pid := range procs {
		if _, err := fmt.Fprintf(fs, "%d\n", pid); err != nil {
			return fmt.Errorf("Cant add pid %d: %w", pid, err)
		}
	}

	return nil
}
