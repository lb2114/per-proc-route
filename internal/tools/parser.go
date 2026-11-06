package tools

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/lb2114/per-proc-route/internal/config"
)

func ParseList(path string) (map[string]int, error) {
	fd, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return map[string]int{}, err
	}
	defer fd.Close()
	res := map[string]int{}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		if len(res) >= config.MaxListRecords {
			return map[string]int{}, fmt.Errorf("process list can contain at most %d paths", config.MaxListRecords)
		}
		line := scanner.Text()
		if !filepath.IsAbs(line) {
			return map[string]int{}, fmt.Errorf("process list must contain absolute paths no longer than %d bytes", config.MaxPathLen)
		}
		if len(line) > config.MaxPathLen {
			return map[string]int{}, fmt.Errorf("process list must contain absolute paths no longer than %d bytes", config.MaxPathLen)
		}
		res[line] = 1
	}
	if err := scanner.Err(); err != nil {
		return res, err
	}
	return res, nil
}

func ParseConfig(path string) (config.UserConfig, error) {
	res := config.UserConfig{}
	fd, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return res, err
	}
	defer fd.Close()
	data := []string{}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		data = append(data, line)
	}
	if err := scanner.Err(); err != nil {
		return res, err
	}
	if len(data) < 2 {
		return res, fmt.Errorf("configuration must contain a gateway address and an interface name on separate lines")
	}
	ip := net.ParseIP(data[0])
	if ip == nil {
		return res, fmt.Errorf("gateway address on the first line must be a valid IP address")
	}
	res.GW = data[0]
	res.InterfaceName = data[1]
	return res, nil
}
