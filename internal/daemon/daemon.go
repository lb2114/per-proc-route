package daemon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/lb2114/per-proc-route/internal/cgroup"
	"github.com/lb2114/per-proc-route/internal/config"
)

func CreateListener() (net.Listener, error) {
	g, err := user.LookupGroup(config.GroupAllowToConn)
	if err != nil {
		return nil, fmt.Errorf("Fail to lookup group: %w", err)
	}

	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil, fmt.Errorf("Fail to conert gid: %w", err)
	}

	if err := os.RemoveAll(config.SockPath + config.SockName); err != nil {
		return nil, err
	}

	if err := os.MkdirAll("/run/ppr", 0770); err != nil {
		return nil, err
	}
	if err := os.Chmod(config.SockPath, 0770); err != nil {
		return nil, fmt.Errorf("Fail to update %s rights: %w", config.SockPath, err)
	}
	if err := os.Chown(config.SockPath, os.Getuid(), gid); err != nil {
		return nil, fmt.Errorf("Fail to update %s ownership: %w", config.SockPath, err)
	}

	l, err := net.Listen("unix", config.SockPath+config.SockName)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(config.SockPath+config.SockName, 0660); err != nil {
		l.Close()
		return nil, err
	}
	if err := os.Chown(config.SockPath+config.SockName, os.Getuid(), gid); err != nil {
		return nil, fmt.Errorf("Fail to update %s ownership: %w", config.SockPath+config.SockName, err)
	}

	return l, nil
}

func parseCmd(line string) (int, error) {
	parts := strings.Split(line, " ")
	if len(parts) < 2 || parts[0] != "add" {
		return -1, fmt.Errorf("Invalid format")
	}
	pid, err := strconv.Atoi(parts[1])
	if err != nil {
		return -1, fmt.Errorf("Invalid format")
	}
	if len(parts[2:]) > 0 {
		return -1, fmt.Errorf("Invalid format")
	}

	return pid, nil
}

func HandleConnection(conn net.Conn, logCh chan error) {
	r := bufio.NewReader(conn)
	defer conn.Close()

	line, err := r.ReadString('\n')
	if err != nil {
		conn.Write([]byte("ERR_CMD\n"))
		logCh <- err
		return
	}

	pid, err := parseCmd(strings.TrimSpace(line))
	if err != nil {
		conn.Write([]byte("ERR_CMD\n"))
		logCh <- err
		return
	}

	err = cgroup.AddPidToCGroup(pid)
	if err != nil {
		conn.Write([]byte("ERR_PID\n"))
		logCh <- err
		return
	}

	conn.Write([]byte("OK\n"))
}
