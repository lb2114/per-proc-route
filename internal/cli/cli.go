package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/lb2114/per-proc-route/internal/config"
)

func sendPidToDaemon(pid int) error {
	conn, err := net.Dial("unix", config.SockPath+config.SockName)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "add %d\n", pid)

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("Fail to read string: %w", err)
	}
	line = strings.TrimSpace(line)

	if line == "OK" {
		return nil
	}
	if line == "ERR_CMD" {
		return fmt.Errorf("Invalid cmd format")
	}
	if line == "ERR_PID" {
		return fmt.Errorf("Daemon fails to add pid into cgroup")
	}

	return fmt.Errorf("Unexpected response from daemon")
}

func Run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("Missing command")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("Failed to look path %s: %w", args[0], err)
	}

	if err := sendPidToDaemon(os.Getpid()); err != nil {
		return fmt.Errorf("Failed to add pid through daemon: %w", err)
	}

	return syscall.Exec(path, args, os.Environ())
}
