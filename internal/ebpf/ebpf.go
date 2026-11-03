package ebpf

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"errors"
	"os"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lb2114/per-proc-route/internal/config"
)


func removeOldLinks() error {
    for _, path := range []string{
        "/sys/fs/bpf/ppr_mark",
        "/sys/fs/bpf/ppr_execve",
        "/sys/fs/bpf/ppr_cpy",
        "/sys/fs/bpf/ppr_del",
    } {
        if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
            return fmt.Errorf("remove BPF link pin %s: %w", path, err)
        }
    }
    return nil
}


func InitEBPF(procsPaths []string) error {
	//remove existing pins before attaching new ones
	err := removeOldLinks()
	if err != nil {
		return err
	}

	var objs markerObjects
	if err := loadMarkerObjects(&objs, nil); err != nil {
		return err
	}

	for _, procPath := range procsPaths {
		key := [config.MaxPathLen + 1]byte{}
		copy(key[:], []byte(procPath))
		if err := objs.markerMaps.ProcsToBypassMap.Put(key, uint8(1)); err != nil {
			return err
		}
	}

	MarkSocket, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup", //attach to root cgroup, so hook will works for every socket creation
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.markerPrograms.MarkSocket,
	})
	if err != nil {
		return err
	}
	defer MarkSocket.Close()

	ExecveTrace, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.markerPrograms.ExecveTrace,
		nil,
	)
	if err != nil {
		return err
	}
	defer ExecveTrace.Close()

	CpyProcessTrace, err := link.AttachTracing(link.TracingOptions{
		Program: objs.markerPrograms.CpyProcessTrace,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return err
	}
	defer CpyProcessTrace.Close()

	DelProcessTrace, err := link.AttachTracing(link.TracingOptions{
		Program: objs.markerPrograms.DelProcessTrace,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return err
	}
	defer DelProcessTrace.Close()

	err = MarkSocket.Pin("/sys/fs/bpf/ppr_mark")
	if (err != nil) {
		return err
	}

	err = ExecveTrace.Pin("/sys/fs/bpf/ppr_execve")
	if (err != nil) {
		MarkSocket.Detach()
		return err
	}

	err = CpyProcessTrace.Pin("/sys/fs/bpf/ppr_cpy")
	if (err != nil) {
		MarkSocket.Detach()
		ExecveTrace.Detach()
		return err
	}

	err = DelProcessTrace.Pin("/sys/fs/bpf/ppr_del")
	if (err != nil) {	
		MarkSocket.Detach()
		ExecveTrace.Detach()
		CpyProcessTrace.Detach()
		return err
	}

	return nil
}
