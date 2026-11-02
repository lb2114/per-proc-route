package tools

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/lb2114/per-proc-route/internal/config"
)

func ParseList(path string) ([]string, error) {
	fd, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return []string{}, err
	}
	res := []string{}
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		if len(res) > config.MaxListRecords {
			return []string{}, fmt.Errorf("Config file can contain only %d records", config.MaxListRecords)
		}
		line := scanner.Text()
		if !filepath.IsAbs(line) {
			return []string{}, fmt.Errorf("Config file must contain only absolute paths no longer than %d bytes (1 byte = 1 ASCII character)", config.MaxPathLen)
		}
		if len(line) > config.MaxPathLen {
			return []string{}, fmt.Errorf("Config file must contain only absolute paths no longer than %d bytes (1 byte = 1 ASCII character)", config.MaxPathLen)
		}
		res = append(res, line)
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
		return res, fmt.Errorf("Invalid config! Wrong configuration! File must contain the gateway address and interface name, each parameter on a new line")
	}
	ip := net.ParseIP(data[0])
	if ip == nil {
		return res, fmt.Errorf("First line in config file must be a valid address!")
	}
	res.GW = data[0]
	res.InterfaceName = data[1]
	return res, nil
}


