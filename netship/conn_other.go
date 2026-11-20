//go:build !darwin

package netship

import (
	psnet "github.com/shirou/gopsutil/v4/net"
)

func socketTable() ([]psnet.ConnectionStat, error) {
	return psnet.Connections("all")
}
