// netprobe is the static connectivity tool the M4 NetworkPolicy oracle runs
// inside cluster pods.  It has no dependencies beyond the Go standard library
// and raw sockets, so it can be copied into the pinned node image and mounted
// into busybox pods without pulling any additional container image.
//
//	netprobe serve --tcp 8080,8001 --sctp 9999
//	netprobe connect --proto tcp|sctp --addr 10.244.0.5 --port 8080 --timeout 3s
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ipprotoSCTP = 132

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: netprobe serve|connect ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "connect":
		connect(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}

func parsePorts(value string) []int {
	ports := []int{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid port", part)
			os.Exit(2)
		}
		ports = append(ports, port)
	}
	return ports
}

func serve(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	tcp := flags.String("tcp", "", "comma separated TCP ports")
	sctp := flags.String("sctp", "", "comma separated SCTP ports")
	_ = flags.Parse(args)
	for _, port := range parsePorts(*tcp) {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcp listen", port, err)
			os.Exit(1)
		}
		go func(port int, listener net.Listener) {
			for {
				conn, err := listener.Accept()
				if err != nil {
					continue
				}
				go func() {
					defer conn.Close()
					_, _ = conn.Write([]byte(fmt.Sprintf("netprobe tcp %d\n", port)))
				}()
			}
		}(port, listener)
	}
	for _, port := range parsePorts(*sctp) {
		fd, err := sctpListen(port)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sctp listen", port, err)
			os.Exit(1)
		}
		go func(port int, fd int) {
			for {
				conn, _, err := syscall.Accept(fd)
				if err != nil {
					continue
				}
				go func(conn int) {
					defer syscall.Close(conn)
					_, _ = syscall.Write(conn, []byte(fmt.Sprintf("netprobe sctp %d\n", port)))
				}(conn)
			}
		}(port, fd)
	}
	fmt.Println(`{"serving":true}`)
	select {}
}

func sctpListen(port int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, ipprotoSCTP)
	if err != nil {
		return -1, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
	if err := syscall.Bind(fd, &syscall.SockaddrInet6{Port: port}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err := syscall.Listen(fd, 16); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

type result struct {
	Proto     string `json:"proto"`
	Addr      string `json:"addr"`
	Port      int    `json:"port"`
	Connected bool   `json:"connected"`
	Banner    string `json:"banner,omitempty"`
	Error     string `json:"error,omitempty"`
	Elapsed   string `json:"elapsed"`
}

func connect(args []string) {
	flags := flag.NewFlagSet("connect", flag.ExitOnError)
	proto := flags.String("proto", "tcp", "tcp or sctp")
	addr := flags.String("addr", "", "destination address")
	port := flags.Int("port", 0, "destination port")
	timeout := flags.Duration("timeout", 3*time.Second, "connect timeout")
	_ = flags.Parse(args)
	started := time.Now()
	out := result{Proto: *proto, Addr: *addr, Port: *port}
	var err error
	switch *proto {
	case "tcp":
		out.Banner, err = tcpConnect(*addr, *port, *timeout)
	case "sctp":
		out.Banner, err = sctpConnect(*addr, *port, *timeout)
	default:
		err = fmt.Errorf("unknown protocol %s", *proto)
	}
	out.Elapsed = time.Since(started).String()
	if err != nil {
		out.Error = err.Error()
	} else {
		out.Connected = true
	}
	encoded, _ := json.Marshal(out)
	fmt.Println(string(encoded))
	if !out.Connected {
		os.Exit(1)
	}
}

func tcpConnect(addr string, port int, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("connected but no banner: %w", err)
	}
	return strings.TrimSpace(string(buffer[:n])), nil
}

// A blocking SCTP connect bounded by an alarm-free deadline: the socket is
// non-blocking and the completion is polled with select(2) semantics.
func sctpConnect(addr string, port int, timeout time.Duration) (string, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", fmt.Errorf("invalid address %s", addr)
	}
	family := syscall.AF_INET6
	var sockaddr syscall.Sockaddr
	if ip4 := ip.To4(); ip4 != nil {
		family = syscall.AF_INET
		var a [4]byte
		copy(a[:], ip4)
		sockaddr = &syscall.SockaddrInet4{Port: port, Addr: a}
	} else {
		var a [16]byte
		copy(a[:], ip.To16())
		sockaddr = &syscall.SockaddrInet6{Port: port, Addr: a}
	}
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK, ipprotoSCTP)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)
	err = syscall.Connect(fd, sockaddr)
	if err != nil && err != syscall.EINPROGRESS {
		return "", err
	}
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("connect timeout after %s", timeout)
		}
		var writable syscall.FdSet
		writable.Bits[fd/64] |= 1 << (uint(fd) % 64)
		tv := syscall.NsecToTimeval(int64(50 * time.Millisecond))
		n, selectErr := syscall.Select(fd+1, nil, &writable, nil, &tv)
		if selectErr != nil && selectErr != syscall.EINTR {
			return "", selectErr
		}
		if n > 0 {
			soErr, getErr := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			if getErr != nil {
				return "", getErr
			}
			if soErr != 0 {
				return "", syscall.Errno(soErr)
			}
			break
		}
	}
	buffer := make([]byte, 64)
	readDeadline := time.Now().Add(timeout)
	for {
		n, readErr := syscall.Read(fd, buffer)
		if readErr == nil && n > 0 {
			return strings.TrimSpace(string(buffer[:n])), nil
		}
		if readErr != nil && readErr != syscall.EAGAIN && readErr != syscall.EWOULDBLOCK {
			return "", fmt.Errorf("connected but no banner: %w", readErr)
		}
		if time.Now().After(readDeadline) {
			return "", fmt.Errorf("connected but no banner within %s", timeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
