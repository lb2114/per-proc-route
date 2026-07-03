package daemon

import (
	"fmt"
	"os"
)

func AddProc(pid int, procs map[int]bool) error {
	fs, err := os.OpenFile("/sys/fs/cgroup/ppr/direct/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer fs.Close()

	if _, err := fmt.Fprintf(fs, "%d\n", pid); err != nil {
		return fmt.Errorf("Cant add pid %d: %w", pid, err)
	}

	procs[pid] = true

	return nil
}

func RemoveProc(pid int, procs map[int]bool) error {
	fs, err := os.OpenFile("/sys/fs/cgroup/ppr/default/cgroup.procs", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer fs.Close()

	if _, err := fmt.Fprintf(fs, "%d\n", pid); err != nil {
		return fmt.Errorf("Cant add pid %d to ppr/default cgroup: %w", pid, err)
	}

	procs[pid] = false

	return nil
}

func ShowProcs(procs map[int]bool) ([]int, error) {
	res := []int{}
	for key, _ := range procs {
		res = append(res, key)
	}

	return res, nil
}
