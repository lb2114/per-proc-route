package routing

import (
	"net"

	"github.com/lb2114/per-proc-route/internal/config"
	"github.com/vishvananda/netlink"
)

func SetupRouting() error {
	link, err := netlink.LinkByName(config.InterfaceName)
	if err != nil {
		return err
	}
	gw := net.ParseIP(config.GW)
	newRoute := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
		Table:     config.TableID,
	}
	err = netlink.RouteReplace(&newRoute)
	if err != nil {
		return err
	}

	newRule := netlink.NewRule()
	newRule.Priority = 1111
	newRule.Mark = uint32(config.Mark)
	newRule.Table = config.TableID

	// if rule already exists delete and ignore error
	_ = netlink.RuleDel(newRule)
	err = netlink.RuleAdd(newRule)
	if err != nil {
		return err
	}

	return nil
}
