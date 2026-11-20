// Package netship is the engine: collector, baseline, enrichment, dashboard.
package netship

import (
	"fmt"
	"hash/fnv"
	"time"
)

// Three levels is enough. A tool that sees a few dozen events a day does not
// need a scale of five.
type Severity int

const (
	SevLow Severity = iota + 1
	SevMedium
	SevHigh
)

func (s Severity) String() string {
	switch s {
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	case SevLow:
		return "low"
	}
	return "unknown"
}

type Process struct {
	GUID       string    `json:"guid"`
	PID        int32     `json:"pid"`
	PPID       int32     `json:"ppid,omitempty"`
	Name       string    `json:"name"`
	Exe        string    `json:"exe,omitempty"`
	Hash       string    `json:"hash,omitempty"`
	Cmdline    string    `json:"cmdline,omitempty"`
	Cwd        string    `json:"cwd,omitempty"`
	User       string    `json:"user,omitempty"`
	ParentGUID string    `json:"parent_guid,omitempty"`
	ParentName string    `json:"parent_name,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`

	// 0..100, about where the binary lives, not about what it talks to.
	OriginRisk int      `json:"origin_risk"`
	OriginWhy  []string `json:"origin_why,omitempty"`
}

// Key is what the baseline remembers: the executable, not the pid. Firefox
// restarted forty times is still one binary.
//
// The pid sits in the fallbacks on purpose. Without it every process we cannot
// attribute to a file would share one baseline entry, and they would keep
// marking each other's destinations as already seen.
func (p Process) Key() string {
	if p.Exe != "" {
		return p.Exe
	}
	if p.Cmdline != "" {
		return "cmd:" + p.Name + " " + firstToken(p.Cmdline) + ":" + itoa(int(p.PID))
	}
	return "name:" + p.Name + ":" + itoa(int(p.PID))
}

// One process reaching one endpoint, deduplicated. Forty thousand socket
// transitions collapse into a couple of hundred of these.
type Flow struct {
	Key         string    `json:"key"`
	ProcessGUID string    `json:"process_guid"`
	RemoteIP    string    `json:"remote_ip"`
	RemotePort  int       `json:"remote_port"`
	Proto       string    `json:"proto"`
	Direction   string    `json:"direction"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Ticks       int       `json:"ticks"`

	// Enriched separates "looked it up, it is a CDN" from "not looked up yet".
	// The first case is what keeps this tool quiet, so the two cannot be one
	// bool called Enriched and a zero ASN.
	Enriched bool   `json:"enriched"`
	ASN      int    `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	Country  string `json:"country,omitempty"`
	Hosting  bool   `json:"hosting"`
	Private  bool   `json:"private,omitempty"`
}

// Every kind answers "what is new", never "what exists".
const (
	KindFirstNetwork = "FIRST_NETWORK"   // binary has never touched the network before
	KindNewRemote    = "NEW_DESTINATION" // known binary, remote it has never used
	KindRiskyOrigin  = "RISKY_ORIGIN"    // ran from temp/downloads/node_modules and went out
	KindNewListener  = "NEW_LISTENER"    // something started listening off-loopback
	KindSuspicious   = "SUSPICIOUS_CMD"  // download-and-execute shaped command line
	KindFanout       = "FANOUT"          // one process, many new remotes, fast
)

type Finding struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Severity    Severity  `json:"severity"`
	ProcessGUID string    `json:"process_guid"`
	ProcessName string    `json:"process_name"`
	FlowKey     string    `json:"flow_key,omitempty"`
	Title       string    `json:"title"`
	Evidence    []string  `json:"evidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
}

// What the UI shows: one card per process, findings and flows under it. The
// alternative is a wall of rows nobody reads.
type Case struct {
	Process  Process   `json:"process"`
	Severity Severity  `json:"severity"`
	Findings []Finding `json:"findings"`
	Flows    []Flow    `json:"flows"`
	Summary  string    `json:"summary"`
}

type Snapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	StartedAt   time.Time `json:"started_at"`
	Learning    bool      `json:"learning"`
	Enriching   bool      `json:"enriching"`
	Demo        bool      `json:"demo"`
	Running     bool      `json:"running"`
	Cases       []Case    `json:"cases"`
	Processes   []Process `json:"processes"`
	Flows       []Flow    `json:"flows"`
	Findings    []Finding `json:"findings"`
	Stats       Stats     `json:"stats"`
}

type Stats struct {
	Processes  int `json:"processes"`
	Flows      int `json:"flows"`
	Findings   int `json:"findings"`
	High       int `json:"high"`
	Medium     int `json:"medium"`
	Low        int `json:"low"`
	Suppressed int `json:"suppressed"` // CDN/cloud contacts we chose not to store
	Lookups    int `json:"lookups"`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func firstToken(s string) string {
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return s[:i]
		}
	}
	return s
}

func shortID(parts ...string) string {
	h := fnv.New64a()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%016x", h.Sum64())
}
