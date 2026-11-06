package ebpf

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"errors"
	"os"
	"fmt"
	"strings"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/lb2114/per-proc-route/internal/config"
)

const (
	PROCS_MAP_PATH   = "/sys/fs/bpf/ppr_procs_map"
	POLICY_MAP_PATH  = "/sys/fs/bpf/ppr_policy_map"
	MARK_LINK_PATH   = "/sys/fs/bpf/ppr_mark"
	EXECVE_LINK_PATH = "/sys/fs/bpf/ppr_execve"
	CPY_LINK_PATH    = "/sys/fs/bpf/ppr_cpy"
	DEL_LINK_PATH    = "/sys/fs/bpf/ppr_del"
)


func removeOldLinks() error {
    for _, path := range []string{
        MARK_LINK_PATH,
        EXECVE_LINK_PATH,
        CPY_LINK_PATH,
        DEL_LINK_PATH,
    } {
        if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
            return fmt.Errorf("remove BPF link pin %s: %w", path, err)
        }
    }
    return nil
}


func InitEBPF(procsPaths map[string]int) error {
	//remove existing pins before attaching new ones
	err := removeOldLinks()
	if err != nil {
		return err
	}

	var objs markerObjects
	if err := loadMarkerObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	for procPath := range procsPaths {
		key := [config.MaxPathLen + 1]byte{}
		copy(key[:], []byte(procPath))
		if err := objs.markerMaps.ProcsToBypassMap.Put(key, uint8(1)); err != nil {
			return err
		}
	}

	//atach maps to bpffs for future access
	err = objs.markerMaps.PolicyMap.Pin(POLICY_MAP_PATH)
	if err != nil {
		return err
	}
	err = objs.markerMaps.ProcsToBypassMap.Pin(PROCS_MAP_PATH)
	if err != nil {
		return err
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

	err = MarkSocket.Pin(MARK_LINK_PATH)
	if (err != nil) {
		return err
	}

	err = ExecveTrace.Pin(EXECVE_LINK_PATH)
	if (err != nil) {
		MarkSocket.Detach()
		return err
	}

	err = CpyProcessTrace.Pin(CPY_LINK_PATH)
	if (err != nil) {
		MarkSocket.Detach()
		ExecveTrace.Detach()
		return err
	}

	err = DelProcessTrace.Pin(DEL_LINK_PATH)
	if (err != nil) {	
		MarkSocket.Detach()
		ExecveTrace.Detach()
		CpyProcessTrace.Detach()
		return err
	}

	return nil
}


func ReloadProcsMap(procsPaths map[string]int) error {
	m, err := ebpf.LoadPinnedMap(PROCS_MAP_PATH, nil)
	if err != nil {
		return err
	}
	defer m.Close()

	for path := range procsPaths {
		key := [config.MaxPathLen + 1]byte{}
		copy(key[:], path)
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}	
	}

	var keys [][config.MaxPathLen + 1]byte
	iter := m.Iterate() 
	var key [config.MaxPathLen + 1]byte
	var val uint8
	for iter.Next(&key, &val) {
		path := strings.TrimRight(string(key[:]), "\x00")
		if _, ok := procsPaths[path]; !ok {
			keys = append(keys, key)
		}	
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
		
	return nil	
}
