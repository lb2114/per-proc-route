package daemon

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/lb2114/per-proc-route/internal/cgroup"
	"github.com/lb2114/per-proc-route/internal/config"
)

func CreateListener() (net.Listener, error) {
	if err := os.RemoveAll(config.SockAddr); err != nil {
		return nil, err
	}

	os.MkdirAll("/run/ppr", 0770)
	l, err := net.Listen("unix", config.SockAddr)
	if err != nil {
		return nil, err
	}
	os.Chmod("/run/ppr", 0777)
	os.Chmod(config.SockAddr, 0666)

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
