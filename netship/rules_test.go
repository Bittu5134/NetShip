package netship

import (
	"testing"
	"time"
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
	if n := len(s.Snapshot(now, false, false).Findings); n != 0 {
		t.Fatalf("%d findings from a CDN contact", n)
	}
	if sup := s.Snapshot(now, false, false).Stats.Suppressed; sup != 1 {
		t.Fatalf("suppressed %d, want 1", sup)
	}
	// The binary is still registered, or its first real contact would look like
	// a first ever contact.
	if s.HasOutboundRemote("/usr/bin/firefox") {
		t.Fatal("a CDN contact was written to the outbound baseline")
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

func TestListenerOnlyWhenRisky(t *testing.T) {
	s, c, now := testCollector(t, 0)
	addProc(s, "g1", "/usr/bin/node", 0, now)
	addListener(s, "g1", 8080, now)

	c.evaluate(now)
	if _, ok := findingsByKind(s, now)[KindNewListener]; ok {
		t.Fatal("a port from a clean origin should not be a finding")
	}

	addProc(s, "g2", "/tmp/build/serve", 65, now)
	addListener(s, "g2", 9090, now)
	c.evaluate(now)
	if _, ok := findingsByKind(s, now)[KindNewListener]; !ok {
		t.Fatal("expected NEW_LISTENER from a risky origin")
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
}
