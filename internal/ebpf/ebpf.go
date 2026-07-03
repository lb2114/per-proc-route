package ebpf

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func LoadEBPF() (*markerObjects, link.Link, error) {
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
