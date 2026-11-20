//go:build darwin

package netship

import (
	"os/exec"

	psnet "github.com/shirou/gopsutil/v4/net"
)

// socketTable reads sockets through lsof.
//
// gopsutil does the same thing on darwin but it stamps the pid it was asked
// for onto every row, which is 0 when you ask for all of them, so every socket
// came back unattributable and the collector threw all of them away.
func socketTable() ([]psnet.ConnectionStat, error) {
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-iUDP", "-F", "pcnPT").Output()
	if err != nil {
		// lsof exits 1 when there is simply nothing to show.
		if len(out) == 0 {
			return nil, err
		}
	}
	return parseLsof(string(out)), nil
}
