package netship

import (
	"testing"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
)

func testCollector(t *testing.T, learning time.Duration) (*Store, *Collector, time.Time) {
	t.Helper()
	now := time.Now()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := NewCollector(s, nil, time.Second, learning)
	c.started = now // a learning window of 0 means the warm-up is already over
	return s, c, now
}

func addProc(s *Store, guid, exe string, risk int, now time.Time) {
	s.UpsertProcess(Process{
		GUID: guid, PID: 4000, Name: exe, Exe: exe,
		FirstSeen: now, LastSeen: now, OriginRisk: risk,
	})
}

func addFlow(s *Store, guid, ip string, port int, now time.Time, hosting bool) {
	s.UpsertFlow(Flow{
		Key: flowKey(guid, ip, port, "TCP"), ProcessGUID: guid,
		RemoteIP: ip, RemotePort: port, Proto: "TCP", Direction: "OUTBOUND",
		FirstSeen: now, LastSeen: now,
		Enriched: true, ASN: 24940, Org: "Hetzner", Country: "DE", Hosting: hosting,
	})
}

func addListener(s *Store, guid string, port int, now time.Time) {
	s.UpsertFlow(Flow{
		Key: "listen|" + guid + "|" + itoa(port) + "/tcp", ProcessGUID: guid,
		RemotePort: port, Proto: "TCP", Direction: "LISTEN",
		FirstSeen: now, LastSeen: now, Enriched: true,
	})
}

func findingsByKind(s *Store, now time.Time) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range s.Snapshot(now, false, false).Findings {
		out[f.Kind] = f
	}
	return out
}

func TestFirstContactFiresOnce(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/curl", 0, now)
	addFlow(s, "g1", "203.0.113.5", 443, now, false)

	c.evaluate(now)
	got := findingsByKind(s, now)
	f, ok := got[KindFirstNetwork]
	if !ok {
		t.Fatalf("no FIRST_NETWORK, got %v", got)
	}
	if f.Severity != SevMedium {
		t.Fatalf("severity %v, want medium for a clean origin", f.Severity)
	}
	if _, ok := got[KindNewRemote]; ok {
		t.Fatal("first contact also reported as a new destination")
	}

	// The second pass has nothing new to say.
	c.evaluate(now)
	if n := len(s.Snapshot(now, false, false).Findings); n != 1 {
		t.Fatalf("%d findings after a second pass, want 1", n)
	}
}

func TestKnownBinaryNewRemote(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/curl", 0, now)
	s.Remember("/usr/bin/curl", "curl", "9.9.9.9:443/tcp", now.Add(-time.Hour))

	addFlow(s, "g1", "203.0.113.5", 443, now, false)
	c.evaluate(now)

	got := findingsByKind(s, now)
	if _, ok := got[KindFirstNetwork]; ok {
		t.Fatal("known binary reported as a first contact")
	}
	if _, ok := got[KindNewRemote]; !ok {
		t.Fatalf("no NEW_DESTINATION, got %v", got)
	}
}

func TestRiskyOriginEscalates(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/tmp/x7f/install.js", 65, now)
	addFlow(s, "g1", "203.0.113.5", 443, now, false)

	c.evaluate(now)
	got := findingsByKind(s, now)
	if f := got[KindFirstNetwork]; f.Severity != SevHigh {
		t.Fatalf("severity %v, want high from a risky origin", f.Severity)
	}
	if _, ok := got[KindRiskyOrigin]; !ok {
		t.Fatalf("no RISKY_ORIGIN, got %v", got)
	}
}

func TestCloudTrafficIsSuppressed(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/firefox", 0, now)
	addFlow(s, "g1", "151.101.1.1", 443, now, true)

	c.evaluate(now)
	snap := s.Snapshot(now, false, false)
	if len(snap.Findings) != 0 {
		t.Fatalf("%d findings from a CDN contact", len(snap.Findings))
	}
	if snap.Stats.Suppressed != 1 {
		t.Fatalf("suppressed %d, want 1", snap.Stats.Suppressed)
	}
	// The endpoint is not stored, but the binary counts as having been out, or
	// its first real contact would be reported as a first ever contact.
	if !s.HasOutboundRemote("/usr/bin/firefox") {
		t.Fatal("a CDN contact did not count as outbound history")
	}
	if _, seen, _ := s.LookupBinary("/usr/bin/firefox", "151.101.1.1:443/tcp"); seen {
		t.Fatal("the CDN endpoint was stored as a remote")
	}
}

func TestCloudOnlyBinaryGetsNewDestination(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/firefox", 0, now)
	addFlow(s, "g1", "151.101.1.1", 443, now, true)
	c.evaluate(now)

	addFlow(s, "g1", "192.0.2.9", 443, now, false)
	c.evaluate(now)

	got := findingsByKind(s, now)
	if _, ok := got[KindFirstNetwork]; ok {
		t.Fatal("a binary that only talked to a CDN was reported as a first contact")
	}
	if _, ok := got[KindNewRemote]; !ok {
		t.Fatalf("expected NEW_DESTINATION, got %v", got)
	}
}

func TestWipedRemoteSetDoesNotLookNew(t *testing.T) {
	s, _, now := testCollector(t, 0)
	s.Remember("/usr/bin/firefox", "firefox", "1.1.1.1:443/tcp", now)
	for i := 0; i < 4100; i++ {
		s.Remember("/usr/bin/firefox", "firefox", "203.0.113."+itoa(i%250)+":"+itoa(1000+i)+"/tcp", now)
	}
	if !s.HasOutboundRemote("/usr/bin/firefox") {
		t.Fatal("the binary stopped counting as outbound after the remote set was wiped")
	}
}

func TestFanout(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/node", 0, now)
	for i := 0; i < 8; i++ {
		addFlow(s, "g1", "203.0.113."+itoa(i+1), 443, now, false)
	}

	c.evaluate(now)
	got := findingsByKind(s, now)
	f, ok := got[KindFanout]
	if !ok {
		t.Fatalf("no FANOUT after eight new destinations, got %v", got)
	}
	if f.Count < 8 {
		t.Fatalf("fan-out counted %d destinations", f.Count)
	}
}

func TestNewListenerFiresOnce(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/node", 0, now)
	addListener(s, "g1", 8080, now)

	c.evaluate(now)
	f, ok := findingsByKind(s, now)[KindNewListener]
	if !ok {
		t.Fatal("a port this binary never bound before should be a finding")
	}
	if f.Severity != SevLow {
		t.Fatalf("severity %v, want low for a clean origin", f.Severity)
	}

	// Second pass: the port is in the baseline now.
	c.evaluate(now)
	if n := len(s.Snapshot(now, false, false).Findings); n != 1 {
		t.Fatalf("%d findings after a second pass, want 1", n)
	}
}

func TestUnconnectedUDPIsNotAListener(t *testing.T) {
	udp := psnet.ConnectionStat{Type: 2, Laddr: psnet.Addr{Port: 5353}}
	if isListener(udp) {
		t.Fatal("a bound udp socket with no peer is not a listener")
	}
	tcp := psnet.ConnectionStat{Type: 1, Laddr: psnet.Addr{Port: 8080}}
	if !isListener(tcp) {
		t.Fatal("a tcp socket with no peer is a listener")
	}
	if !isListener(psnet.ConnectionStat{Type: 2, Status: "LISTEN"}) {
		t.Fatal("udp in LISTEN state is still a listener")
	}
}

func TestDemoOnlyShowsWhatTheRulesProduce(t *testing.T) {
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	SeedDemo(s)
	snap := s.Snapshot(time.Now(), false, false)
	for _, f := range snap.Findings {
		if f.Kind != KindSuspicious {
			continue
		}
		var cmd string
		for _, p := range snap.Processes {
			if p.GUID == f.ProcessGUID {
				cmd = p.Cmdline
			}
		}
		if _, ok := suspiciousCmdline(cmd); !ok {
			t.Fatalf("the demo shows a suspicious line the rules cannot produce: %q", cmd)
		}
	}
}

func TestWarmUpStaysQuiet(t *testing.T) {
	s, c, now := testCollector(t, time.Hour)
	addProc(s, "g1", "/usr/bin/curl", 0, now)
	addFlow(s, "g1", "203.0.113.5", 443, now, false)

	c.evaluate(now)
	if n := len(s.Snapshot(now, false, false).Findings); n != 0 {
		t.Fatalf("%d findings during warm-up", n)
	}
	known, seen, _ := s.LookupBinary("/usr/bin/curl", "203.0.113.5:443/tcp")
	if !known || !seen {
		t.Fatal("warm-up did not record the destination")
	}
}

func TestUnclassifiedLowRiskIsIgnored(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/curl", 0, now)
	s.UpsertFlow(Flow{
		Key: flowKey("g1", "203.0.113.5", 443, "TCP"), ProcessGUID: "g1",
		RemoteIP: "203.0.113.5", RemotePort: 443, Proto: "TCP", Direction: "OUTBOUND",
		FirstSeen: now.Add(-time.Minute), LastSeen: now,
	})

	c.evaluate(now)
	if n := len(s.Snapshot(now, false, false).Findings); n != 0 {
		t.Fatalf("%d findings from unresolved traffic on a clean origin", n)
	}
	// It must not be written into the baseline either, or the first contact
	// after a DNS outage would look like a destination we already know.
	if s.HasOutboundRemote("/usr/bin/curl") {
		t.Fatal("unresolved traffic was recorded as outbound history")
	}
}

func TestClassifiedLaterStillFires(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/curl", 0, now)
	key := flowKey("g1", "203.0.113.5", 443, "TCP")
	s.UpsertFlow(Flow{
		Key: key, ProcessGUID: "g1", RemoteIP: "203.0.113.5", RemotePort: 443,
		Proto: "TCP", Direction: "OUTBOUND", FirstSeen: now, LastSeen: now,
	})

	c.evaluate(now)
	if n := len(s.Snapshot(now, false, false).Findings); n != 0 {
		t.Fatalf("%d findings before the lookup answered", n)
	}

	// The answer lands; the next pass has to judge it.
	s.EnrichFlow(key, ASNInfo{ASN: 24940, Org: "Hetzner", Country: "DE"})
	c.evaluate(now)
	if _, ok := findingsByKind(s, now)[KindFirstNetwork]; !ok {
		t.Fatal("a flow classified after its first pass was never judged")
	}
}
