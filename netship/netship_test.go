package netship

import (
	"net/http"
	"os"
	"testing"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
)

func TestOriginRisk(t *testing.T) {
	cases := []struct {
		name          string
		exe, cwd, cmd string
		want          int
		wantWhy       string
	}{
		{"plain system binary", "/usr/bin/ls", "/home/bittu", "ls -la", 0, ""},
		{"temp dir", "/tmp/x/run", "/tmp/x", "./run", 45, "runs from a temporary directory"},
		{"downloads", "/usr/bin/python3", "/home/bittu/Downloads/thing", "python3 setup.py", 30, "runs from a downloads folder"},
		{"node_modules", "/usr/bin/node", "/home/bittu/app/node_modules/x", "node index.js", 30, "runs from a package install directory"},
		{"no exe", "", "/home/bittu", "something", 20, "executable path unavailable"},
		{"opt tmpx is not tmp", "/opt/tmpx/bin", "/opt/tmpx", "./bin", 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := originRisk(c.exe, c.cwd, c.cmd)
			if got < c.want {
				t.Fatalf("score %d, wanted at least %d (%v)", got, c.want, why)
			}
			if c.wantWhy != "" && !hasString(why, c.wantWhy) {
				t.Fatalf("missing reason %q in %v", c.wantWhy, why)
			}
		})
	}
}

func hasString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		host   string
		want   bool
	}{
		{"no header, curl or a form post", "", "127.0.0.1:8787", true},
		{"this dashboard", "http://127.0.0.1:8787", "127.0.0.1:8787", true},
		{"another site", "https://evil.example", "127.0.0.1:8787", false},
		{"same host, other port", "http://127.0.0.1:3000", "127.0.0.1:8787", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &http.Request{Host: c.host, Header: http.Header{}}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := sameOrigin(r); got != c.want {
				t.Fatalf("sameOrigin = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPrivateRanges(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.0.5", "100.64.0.1", "::1", "fe80::1", "not-an-ip"} {
		if !IsPrivateOrLocal(ip) {
			t.Errorf("%s should be local", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "203.0.113.9", "2606:4700::1111"} {
		if IsPrivateOrLocal(ip) {
			t.Errorf("%s should not be local", ip)
		}
	}
}

func TestNoiseFilter(t *testing.T) {
	me := int32(999)
	if !isNoise(psnet.ConnectionStat{Pid: 0}, me) {
		t.Error("unowned socket is noise")
	}
	if !isNoise(psnet.ConnectionStat{Pid: me}, me) {
		t.Error("our own sockets are noise")
	}
	if !isNoise(psnet.ConnectionStat{Pid: 10, Status: "TIME_WAIT"}, me) {
		t.Error("TIME_WAIT is noise")
	}
	if isNoise(psnet.ConnectionStat{Pid: 10, Status: "SYN_SENT"}, me) {
		t.Error("SYN_SENT is an attempt, keep it")
	}
}

func TestBaselineSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()

	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Remember("/usr/bin/curl", "curl", "1.2.3.4:443/tcp", now)
	if !s.HasOutboundRemote("/usr/bin/curl") {
		t.Fatal("outbound remote not registered")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	again, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	known, seen, first := again.LookupBinary("/usr/bin/curl", "1.2.3.4:443/tcp")
	if !known || !seen {
		t.Fatalf("baseline lost: known=%v seen=%v", known, seen)
	}
	if first.IsZero() {
		t.Fatal("first seen not restored")
	}
}

func TestCorruptBaselineIsMovedAside(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/baseline.json", []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.Baselines(); n != 0 {
		t.Fatalf("expected empty baseline, got %d", n)
	}
	if _, err := os.Stat(dir + "/baseline.json.corrupt"); err != nil {
		t.Fatal("corrupt file was not kept")
	}
}
