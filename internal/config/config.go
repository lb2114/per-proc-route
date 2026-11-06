package config

const TableID = 2114
const Mark = 0x55
const SockPath = "/run/ppr/"
const SockName = "pprd.sock"
const GroupAllowToConn = "ppr"

const MaxPathLen = 255
const MaxListRecords = 1024

type UserConfig struct {
	GW            string
	InterfaceName string
}
