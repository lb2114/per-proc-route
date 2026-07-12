package ebpf

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/lb2114/per-proc-route/internal/cgroup"
	"github.com/lb2114/per-proc-route/internal/config"
)

type MarkerLinks struct {
	MarkSocketLink  link.Link
	ExecveTraceLink link.Link
}

func (lnks *MarkerLinks) Close() error {
	if err := lnks.MarkSocketLink.Close(); err != nil {
		return err
	}
	return lnks.ExecveTraceLink.Close()
}

func InitEBPF(procsPaths []string) (*markerObjects, *MarkerLinks, error) {
	var objs markerObjects
	if err := loadMarkerObjects(&objs, nil); err != nil {
		return nil, nil, err
	}

	var lnks MarkerLinks
	var err error

	for _, procPath := range procsPaths {
		key := [config.MaxPathLen + 1]byte{}
		copy(key[:], []byte(procPath))
		if err := objs.markerMaps.ProcsToBypassMap.Put(key, uint8(1)); err != nil {
			return nil, nil, err
		}
	}

	lnks.MarkSocketLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup/ppr/direct",
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: objs.markerPrograms.MarkSocket,
	})
	if err != nil {
		return nil, nil, err
	}

	lnks.ExecveTraceLink, err = link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.markerPrograms.ExecveTrace,
		nil,
	)

	if err != nil {
		return nil, nil, err
	}

	return &objs, &lnks, nil
}

func UserspaceEBPF(objs *markerObjects, logCh chan error) {
	reader, err := ringbuf.NewReader(objs.markerMaps.UnregPidsMap)
	if err != nil {
		logCh <- fmt.Errorf("Ebpf userspace error: %w", err)
		return
	}
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			logCh <- fmt.Errorf("Ebpf userspace error: %w", err)
			return
		}
		pid := *(*int)(unsafe.Pointer(&record.RawSample[0]))
		if err = cgroup.AddPidToCGroup(pid); err != nil {
			logCh <- err
			return
		}
	}
}
