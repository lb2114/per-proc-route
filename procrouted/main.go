package main

//go:generate go tool bpf2go -tags linux marker marker.c

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

type Proc struct {
	name string
	pid  int64
}

const GW = "192.168.0.1"
const TableID = 2114
const InterfaceName = "wlan0"
const Mark = 0x55

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

func setupRouting() error {
	link, err := netlink.LinkByName(InterfaceName)
	if err != nil {
		return err
	}
	gw := net.ParseIP(GW)
	newRoute := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
		Table:     TableID,
	}
	err = netlink.RouteReplace(&newRoute)
	if err != nil {
		return err
	}

	newRule := netlink.NewRule()
	newRule.Priority = 1111
	newRule.Mark = uint32(Mark)
	newRule.Table = TableID

	// if rule already exists delete and ignore error
	_ = netlink.RuleDel(newRule)
	err = netlink.RuleAdd(newRule)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	err := setupRouting()
	if err != nil {
		log.Fatal("Fail to setup routing tables and policy rules:", err)
		os.Exit(1)
	}

	err = setupCgroup()
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
}
