package netship

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Store owns all the mutable state. The collector is the only writer and the
// HTTP handlers only ever call Snapshot, so there is one mutex and no lock
// ordering to think about.
type Store struct {
	mu     sync.RWMutex
	saveMu sync.Mutex

	dir      string
	baseline map[string]*Binary // the memory that outlives a run
	procs    map[string]*Process
	flows    map[string]*Flow
	findings map[string]*Finding

	started  time.Time
	suppress int
}

// Binary is what survives a restart: the remotes this executable has been seen
// talking to. A tool that forgets on exit can only show you a firewall log.
type Binary struct {
	Key       string          `json:"key"`
	Name      string          `json:"name,omitempty"`
	FirstSeen time.Time       `json:"first_seen"`
	LastSeen  time.Time       `json:"last_seen"`
	Remotes   map[string]bool `json:"remotes"` // "1.2.3.4:443/tcp"
}

type baselineFile struct {
	Version  int                `json:"version"`
	Binaries map[string]*Binary `json:"binaries"`
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:      dir,
		baseline: map[string]*Binary{},
		procs:    map[string]*Process{},
		flows:    map[string]*Flow{},
		findings: map[string]*Finding{},
		started:  time.Now(),
	}
	s.load()
	return s, nil
}

func (s *Store) load() {
	raw, err := os.ReadFile(filepath.Join(s.dir, "baseline.json"))
	if err != nil {
		return
	}
	var bf baselineFile
	if json.Unmarshal(raw, &bf) != nil {
		// A corrupt baseline must not read as "nothing ever seen", or every
		// remote on the machine comes back as FIRST_NETWORK. Move it aside and
		// leave the damage where someone can find it.
		_ = os.Rename(filepath.Join(s.dir, "baseline.json"),
			filepath.Join(s.dir, "baseline.json.corrupt"))
		return
	}
	for k, v := range bf.Binaries {
		if v.Remotes == nil {
			v.Remotes = map[string]bool{}
		}
		s.baseline[k] = v
	}
}

// Save is called on a timer and on shutdown, never per event. An fsync per
// socket transition is how a monitor ends up in its own top-talkers list.
func (s *Store) Save() error {
	// Only one Save at a time: a shared temp path means the second rename can
	// move the first save's half-written file into place.
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	bf := baselineFile{Version: 1, Binaries: make(map[string]*Binary, len(s.baseline))}
	for k, v := range s.baseline {
		cp := *v
		// Remotes has to be copied properly. A shallow copy still points at
		// the live map the collector is mutating under mu, and marshalling
		// outside the lock would race it.
		cp.Remotes = make(map[string]bool, len(v.Remotes))
		for r := range v.Remotes {
			cp.Remotes[r] = true
		}
		bf.Binaries[k] = &cp
	}
	s.mu.RUnlock()

	raw, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "baseline.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "baseline.json"))
}

func (s *Store) Baselines() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.baseline)
}

// Prune bounds the live working set; baseline memory survives, except for
// binaries that have been quiet for months. It returns the keys the collector
// has to drop from its own maps, otherwise a pruned process could be reported
// twice.
func (s *Store) Prune(olderThan time.Duration, now time.Time) (flowKeys, procGUIDs []string) {
	cutoff := now.Add(-olderThan)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Findings follow their process, not the clock: a finding whose process is
	// still around stays visible however long ago it fired, because report()
	// only fires once per kind. A finding whose process is gone has no case to
	// live in and goes with it.
	dead := make(map[string]bool)
	for guid, p := range s.procs {
		if p.LastSeen.Before(cutoff) {
			dead[guid] = true
			delete(s.procs, guid)
			procGUIDs = append(procGUIDs, guid)
		}
	}
	for key, f := range s.flows {
		if f.LastSeen.Before(cutoff) {
			delete(s.flows, key)
			flowKeys = append(flowKeys, key)
		}
	}
	for id, f := range s.findings {
		if dead[f.ProcessGUID] {
			delete(s.findings, id)
		}
	}

	// Short-lived processes mint one baseline key each, so without this the
	// file grows with uptime and every save gets slower.
	const baselineTTL = 90 * 24 * time.Hour
	baselineCutoff := now.Add(-baselineTTL)
	for key, b := range s.baseline {
		if b.LastSeen.Before(baselineCutoff) {
			delete(s.baseline, key)
		}
	}
	return flowKeys, procGUIDs
}

func (s *Store) LookupBinary(key, remote string) (known, seenRemote bool, first time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.baseline[key]
	if !ok {
		return false, false, time.Time{}
	}
	return true, b.Remotes[remote], b.FirstSeen
}

func (s *Store) Remember(key, name, remote string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.baseline[key]
	if !ok {
		b = &Binary{Key: key, FirstSeen: now, Remotes: map[string]bool{}}
		s.baseline[key] = b
	}
	if b.Name == "" {
		b.Name = name
	}
	b.LastSeen = now
	if remote != "" && !b.Remotes[remote] {
		// A browser can reach thousands of these. Oldest-first eviction would
		// need ordering we do not keep, so the set is dropped whole and that
		// one binary learns its remotes again.
		if len(b.Remotes) > 4000 {
			b.Remotes = map[string]bool{}
		}
		b.Remotes[remote] = true
	}
}

func (s *Store) HasOutboundRemote(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.baseline[key]
	if !ok {
		return false
	}
	for r := range b.Remotes {
		if !strings.HasPrefix(r, "listen:") {
			return true
		}
	}
	return false
}

func (s *Store) UpsertProcess(p Process) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.procs[p.GUID]; ok {
		old.LastSeen = p.LastSeen
		old.PID = p.PID
		// Hashing is async, so most ticks arrive with no hash. Only overwrite
		// when there is one, or the next tick wipes what the hasher filled in.
		if p.Hash != "" {
			old.Hash = p.Hash
		}
		return
	}
	s.procs[p.GUID] = &p
}

func (s *Store) UpsertFlow(f Flow) *Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.flows[f.Key]; ok {
		old.LastSeen = f.LastSeen
		old.Ticks++
		if f.Enriched {
			old.Enriched, old.ASN, old.Org, old.Country, old.Hosting = f.Enriched, f.ASN, f.Org, f.Country, f.Hosting
		}
		return old
	}
	s.flows[f.Key] = &f
	return &f
}

func (s *Store) EnrichFlow(key string, info ASNInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.flows[key]; ok {
		f.Enriched = true
		f.ASN, f.Org, f.Country, f.Hosting = info.ASN, info.Org, info.Country, info.Hosting
	}
}

// Cloud and CDN remotes we dropped instead of storing. The count is shown in
// the UI, so the filter can be seen working.
func (s *Store) Suppress(n int) {
	s.mu.Lock()
	s.suppress += n
	s.mu.Unlock()
}

func (s *Store) AddFinding(f Finding) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.findings[f.ID]; ok {
		old.LastSeen = f.LastSeen
		old.Count++
		return false
	}
	s.findings[f.ID] = &f
	return true
}

func (s *Store) Snapshot(now time.Time, learning, enriching bool) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := Snapshot{
		GeneratedAt: now,
		StartedAt:   s.started,
		Learning:    learning,
		Enriching:   enriching,
		Stats: Stats{
			Processes:  len(s.procs),
			Flows:      len(s.flows),
			Findings:   len(s.findings),
			Suppressed: s.suppress,
		},
	}
	for _, p := range s.procs {
		snap.Processes = append(snap.Processes, *p)
	}
	for _, f := range s.flows {
		snap.Flows = append(snap.Flows, *f)
	}
	for _, f := range s.findings {
		snap.Findings = append(snap.Findings, *f)
		switch f.Severity {
		case SevHigh:
			snap.Stats.High++
		case SevMedium:
			snap.Stats.Medium++
		case SevLow:
			snap.Stats.Low++
		}
	}

	sort.Slice(snap.Processes, func(i, j int) bool { return snap.Processes[i].LastSeen.After(snap.Processes[j].LastSeen) })
	sort.Slice(snap.Flows, func(i, j int) bool { return snap.Flows[i].LastSeen.After(snap.Flows[j].LastSeen) })
	sort.Slice(snap.Findings, func(i, j int) bool {
		if snap.Findings[i].Severity != snap.Findings[j].Severity {
			return snap.Findings[i].Severity > snap.Findings[j].Severity
		}
		return snap.Findings[i].LastSeen.After(snap.Findings[j].LastSeen)
	})

	snap.Cases = s.casesLocked()
	return snap
}

// One process, one card, however many sockets it opened.
func (s *Store) casesLocked() []Case {
	byProc := map[string][]Finding{}
	for _, f := range s.findings {
		byProc[f.ProcessGUID] = append(byProc[f.ProcessGUID], *f)
	}
	flowsByProc := map[string][]Flow{}
	for _, f := range s.flows {
		flowsByProc[f.ProcessGUID] = append(flowsByProc[f.ProcessGUID], *f)
	}
	cases := make([]Case, 0, len(byProc))
	for guid, fs := range byProc {
		p, ok := s.procs[guid]
		if !ok {
			continue
		}
		sort.Slice(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
		c := Case{Process: *p, Findings: fs, Flows: flowsByProc[guid]}
		for _, f := range fs {
			if f.Severity > c.Severity {
				c.Severity = f.Severity
			}
		}
		c.Summary = fs[0].Title
		if len(fs) > 1 {
			c.Summary = fs[0].Title + " (+" + itoa(len(fs)-1) + " more)"
		}
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Severity != cases[j].Severity {
			return cases[i].Severity > cases[j].Severity
		}
		return cases[i].Process.LastSeen.After(cases[j].Process.LastSeen)
	})
	return cases
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

// processMeta caches the per-pid lookups. Re-reading exe, cmdline, cwd and user
// for 400 pids every two seconds was most of the CPU this thing used.
type processMeta struct {
	guid       string
	ppid       int32
	name       string
	exe        string
	cmdline    string
	cwd        string
	user       string
	created    int64
	originRisk int
	originWhy  []string
	fetched    time.Time
}

type metaCache struct {
	mu sync.RWMutex
	m  map[int32]*processMeta
}

func newMetaCache() *metaCache { return &metaCache{m: map[int32]*processMeta{}} }

// Get refreshes when the pid is unknown, or when its start time no longer
// matches: a pid reused inside one poll is a different process wearing the same
// number, and CreateTime is the cheapest way to tell.
func (c *metaCache) Get(pid int32) *processMeta {
	c.mu.RLock()
	meta, ok := c.m[pid]
	c.mu.RUnlock()
	if ok {
		if p, err := process.NewProcess(pid); err == nil {
			if created, _ := p.CreateTime(); created != 0 && created != meta.created {
				ok = false
			}
		}
	}
	if !ok {
		fresh := fetchMeta(pid)
		c.mu.Lock()
		c.m[pid] = fresh
		c.mu.Unlock()
		return fresh
	}
	return meta
}

func (c *metaCache) Prune(alive map[int32]bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid := range c.m {
		if !alive[pid] {
			delete(c.m, pid)
		}
	}
}

func fetchMeta(pid int32) *processMeta {
	meta := &processMeta{}
	p, err := process.NewProcess(pid)
	if err != nil {
		// Gone before we could name it. Keep it keyed by pid so these do not
		// all share one baseline and hide each other's remotes, and still run
		// the origin check so "no executable path" is not silently dropped.
		meta.name = "unresolved"
		meta.guid = shortID("unresolved", itoa(int(pid)))
		meta.originRisk, meta.originWhy = originRisk("", "", "")
		return meta
	}
	meta.name, _ = p.Name()
	if meta.name == "" {
		meta.name = "unknown"
	}
	meta.exe, _ = p.Exe()
	meta.cmdline, _ = p.Cmdline()
	meta.cwd, _ = p.Cwd()
	meta.user, _ = p.Username()
	meta.created, _ = p.CreateTime()
	meta.ppid, _ = p.Ppid()
	meta.guid = shortID(meta.exe, itoa(int(meta.created)), itoa(int(pid)))
	meta.originRisk, meta.originWhy = originRisk(meta.exe, meta.cwd, meta.cmdline)
	meta.fetched = time.Now()
	return meta
}

// Everything here was measured on a real machine: in 60 seconds the first
// version logged 356 rows, 70 of them sockets that had already closed and 69
// with no owning process. None of it was a finding.
func isNoise(conn psnet.ConnectionStat, self int32) bool {
	if conn.Pid <= 0 || conn.Pid == self {
		return true
	}
	switch conn.Status {
	case "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "FIN_WAIT1", "FIN_WAIT2", "CLOSING":
		return true
	}
	// SYN_SENT stays: an attempt that never completes is still an attempt, and
	// filtering these out is exactly how a polling monitor misses short
	// lived beacons.
	return false
}

func isListener(conn psnet.ConnectionStat) bool {
	return conn.Status == "LISTEN" || (conn.Raddr.IP == "" && conn.Raddr.Port == 0 && conn.Laddr.Port != 0)
}

// One goroutine, one loop, no subprocess and nothing to supervise.
func (c *Collector) Run(ctx context.Context) error {
	c.hasher.Start(ctx)
	ticker := time.NewTicker(c.Interval)
	defer ticker.Stop()
	save := time.NewTicker(30 * time.Second)
	defer save.Stop()

	c.tick(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return c.store.Save()
		case <-save.C:
			if err := c.store.Save(); err != nil {
				return err
			}
		case <-ticker.C:
			if err := c.tick(ctx, time.Now()); err != nil {
				// A process that vanished mid-poll is not fatal, the next tick
				// picks up whatever is still there.
				continue
			}
		}
	}
}

// So the demo scenario goes through the same write path as live telemetry.
func (s *Store) UpsertFlowsForDemo(fs ...Flow) {
	for _, f := range fs {
		s.UpsertFlow(f)
	}
}
