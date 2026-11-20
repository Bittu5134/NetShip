package netship

import (
	"net"
	"strconv"
	"strings"

	psnet "github.com/shirou/gopsutil/v4/net"
)

// parseLsof reads the machine readable output of
//
//	lsof -nP -iTCP -iUDP -F pcnPT
//
// which groups fields by process: p<pid>, then c<command>, f<fd>, P<proto>,
// n<local>-><remote>, TST=<state> for every socket that process owns.
func parseLsof(out string) []psnet.ConnectionStat {
	var conns []psnet.ConnectionStat
	var cur psnet.ConnectionStat

	flush := func(keepPid bool) {
		if cur.Pid > 0 && cur.Laddr.Port != 0 {
			conns = append(conns, cur)
		}
		pid := cur.Pid
		cur = psnet.ConnectionStat{}
		if keepPid {
			cur.Pid = pid
		}
	}

	for _, line := range strings.Split(out, "\n") {
		if len(line) < 2 {
			continue
		}
		kind, val := line[0], line[1:]
		switch kind {
		case 'p':
			flush(false)
			pid, err := strconv.ParseInt(val, 10, 32)
			if err != nil {
				continue
			}
			cur.Pid = int32(pid)
		case 'f':
			// A new file descriptor is a new socket, and the rest of its fields
			// follow it. Flush here too, or one process's sockets overwrite
			// each other and only the last one survives.
			flush(true)
			if fd, err := strconv.ParseUint(val, 10, 32); err == nil {
				cur.Fd = uint32(fd)
			}
		case 'P':
			if strings.EqualFold(val, "TCP") {
				cur.Type = 1
			} else {
				cur.Type = 2
			}
		case 'n':
			local, remote, _ := strings.Cut(val, "->")
			cur.Laddr = lsofAddr(local)
			if remote != "" {
				cur.Raddr = lsofAddr(remote)
			}
		case 'T':
			if state, ok := strings.CutPrefix(val, "ST="); ok {
				cur.Status = state
			}
		}
	}
	flush(false)
	return conns
}

// lsof writes addresses as "*:8080", "127.0.0.1:8080" or "[::1]:8080". A star
// or a missing host means every interface, which we keep as an empty IP.
func lsofAddr(s string) psnet.Addr {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return psnet.Addr{}
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return psnet.Addr{}
	}
	if host == "*" {
		host = ""
	}
	return psnet.Addr{IP: host, Port: uint32(n)}
}
