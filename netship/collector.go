package netship

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Collector polls sockets and turns the difference into findings. One goroutine
// owns every write.
type Collector struct {
	store  *Store
	enr    *Enricher
	hasher *Hasher

	Interval  time.Duration
	Learning  time.Duration
	Self      int32
	OnFinding func(Finding)

	meta      *metaCache
	started   time.Time
	evaluated map[string]bool        // flow key -> novelty already judged
	fanout    map[string][]time.Time // processGUID -> recent new-remote times
}

func NewCollector(store *Store, enr *Enricher, interval, learning time.Duration) *Collector {
	return &Collector{
		store:     store,
		enr:       enr,
		hasher:    NewHasher(),
		Interval:  interval,
		Learning:  learning,
		Self:      int32(os.Getpid()),
		meta:      newMetaCache(),
		started:   time.Now(),
		evaluated: map[string]bool{},
		fanout:    map[string][]time.Time{},
	}
}

func (c *Collector) InLearning(now time.Time) bool { return now.Sub(c.started) < c.Learning }

// How long dead processes, closed flows and their findings stay in the live set.
const liveTTL = 30 * time.Minute

func (c *Collector) tick(ctx context.Context, now time.Time) error {
	conns, err := socketTable()
	if err != nil {
		return err
	}

	alive := make(map[int32]bool, len(conns))
	for _, conn := range conns {
		alive[conn.Pid] = true
		if isNoise(conn, c.Self) {
			continue
		}
		meta := c.meta.Get(conn.Pid)
		proc := Process{
			GUID:       meta.guid,
			PID:        conn.Pid,
			PPID:       meta.ppid,
			Name:       meta.name,
			Exe:        meta.exe,
			Cmdline:    meta.cmdline,
			Cwd:        meta.cwd,
			User:       meta.user,
			FirstSeen:  now,
			LastSeen:   now,
			OriginRisk: meta.originRisk,
			OriginWhy:  meta.originWhy,
		}
		// Never hash inside fetchMeta: it reads the whole binary and would block
		// the poll. Ask here, pick the sum up on a later tick.
		if meta.exe != "" {
			if sum, ok := c.hasher.Get(meta.exe); ok {
				proc.Hash = sum
			} else {
				c.hasher.Request(meta.exe)
			}
		}
		if meta.ppid > 0 {
			if pm := c.meta.Get(meta.ppid); pm != nil {
				proc.ParentGUID, proc.ParentName = pm.guid, pm.name
				// Parents rarely own sockets of their own. Keep them in the meta
				// cache, or every tick refetches exe, cwd and the origin stat.
				alive[meta.ppid] = true
			}
		}
		c.store.UpsertProcess(proc)

		if isListener(conn) {
			// A dev server on 127.0.0.1 is none of our business. 0.0.0.0 and
			// :: are: other machines can reach those.
			if isLoopbackAddr(conn.Laddr.IP) {
				continue
			}
			c.store.UpsertFlow(Flow{
				Key:         "listen|" + proc.GUID + "|" + strconv.Itoa(int(conn.Laddr.Port)) + "/" + protoOf(conn),
				ProcessGUID: proc.GUID,
				RemotePort:  int(conn.Laddr.Port),
				Proto:       protoOf(conn),
				Direction:   "LISTEN",
				FirstSeen:   now,
				LastSeen:    now,
				Enriched:    true, // listeners are not looked up
			})
			continue
		}

		remote := conn.Raddr.IP
		if remote == "" || IsPrivateOrLocal(remote) {
			continue
		}

		flow := Flow{
			Key:         flowKey(proc.GUID, remote, int(conn.Raddr.Port), protoOf(conn)),
			ProcessGUID: proc.GUID,
			RemoteIP:    remote,
			RemotePort:  int(conn.Raddr.Port),
			Proto:       protoOf(conn),
			Direction:   "OUTBOUND",
			FirstSeen:   now,
			LastSeen:    now,
		}
		if info, ok := c.enr.Cached(remote); ok {
			flow.Enriched = true
			flow.ASN, flow.Org, flow.Country, flow.Hosting = info.ASN, info.Org, info.Country, info.Hosting
		}
		stored := c.store.UpsertFlow(flow)

		if !stored.Enriched {
			c.enr.Request(remote)
		}
	}

	c.meta.Prune(alive)
	// Baseline memory lives 90 days (see Store.Prune); what is bounded here is
	// the working set. Flow keys and process GUIDs that leave the store also
	// have to leave these maps, or they grow one entry per socket for as long as
	// the thing runs.
	flowKeys, procGUIDs := c.store.Prune(liveTTL, now)
	for _, k := range flowKeys {
		delete(c.evaluated, k)
	}
	for _, guid := range procGUIDs {
		delete(c.fanout, guid)
	}
	for guid, times := range c.fanout {
		kept := times[:0]
		for _, t := range times {
			if now.Sub(t) <= time.Minute {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(c.fanout, guid)
		} else {
			c.fanout[guid] = kept
		}
	}
	c.evaluate(now)
	return nil
}

// Judges every flow whose classification has landed. Findings come from the
// baseline, never from the raw socket list, which is why the UI stays small on a
// busy machine.
func (c *Collector) evaluate(now time.Time) {
	learning := c.InLearning(now)
	snap := c.store.Snapshot(now, learning, false)

	procs := make(map[string]Process, len(snap.Processes))
	for _, p := range snap.Processes {
		procs[p.GUID] = p
	}

	// The command line belongs to the process, not to a socket. Checking it here
	// also catches `sh -c "curl ... | sh"`, where the shell holds the pipe and
	// curl holds the connection, and it does not care what the ASN says.
	if !learning {
		for _, p := range procs {
			if why, ok := suspiciousCmdline(p.Cmdline); ok {
				c.report(Finding{
					ID: shortID("cmd", p.GUID), Kind: KindSuspicious,
					Severity: SevHigh, ProcessGUID: p.GUID, ProcessName: p.Name,
					Title:     "Download-and-execute shaped command line",
					Evidence:  []string{why, truncate(p.Cmdline, 240)},
					FirstSeen: now, LastSeen: now, Count: 1,
				}, p)
			}
		}
	}

	const unclassifiedGrace = 20 * time.Second
	for i := range snap.Flows {
		f := &snap.Flows[i]
		if c.evaluated[f.Key] {
			continue
		}
		// A failed lookup must not hide traffic. After a short grace period the
		// flow is judged as unclassified, and only escalated when the origin was
		// already bad.
		unclassified := !f.Enriched
		if unclassified {
			// The lookup may have landed since the flow was stored. Apply it
			// here, or a flow whose socket closed early stays unclassified.
			if info, ok := c.enr.Cached(f.RemoteIP); ok {
				c.store.EnrichFlow(f.Key, info)
				f.Enriched, unclassified = true, false
				f.ASN, f.Org, f.Country, f.Hosting = info.ASN, info.Org, info.Country, info.Hosting
			}
		}
		if unclassified {
			if now.Sub(f.FirstSeen) < unclassifiedGrace {
				continue
			}
			c.enr.Request(f.RemoteIP)
		}
		proc, ok := procs[f.ProcessGUID]
		if !ok {
			continue
		}

		if f.Direction == "LISTEN" {
			c.evaluated[f.Key] = true
			listenKey := "listen:" + itoa(f.RemotePort) + "/" + strings.ToLower(f.Proto)
			_, seen, _ := c.store.LookupBinary(proc.Key(), listenKey)
			c.store.Remember(proc.Key(), proc.Name, listenKey, now)
			if learning || seen {
				continue
			}
			sev := SevLow
			if proc.OriginRisk >= 40 {
				sev = SevMedium
			}
			c.report(Finding{
				ID: shortID("listener", proc.GUID, itoa(f.RemotePort)), Kind: KindNewListener,
				Severity:    sev,
				ProcessGUID: proc.GUID, ProcessName: proc.Name, FlowKey: f.Key,
				Title:     "New listener on port " + itoa(f.RemotePort),
				Evidence:  append([]string{"bound " + f.Proto + " " + itoa(f.RemotePort)}, proc.OriginWhy...),
				FirstSeen: now, LastSeen: now, Count: 1,
			}, proc)
			continue
		}

		// CDN and cloud traffic is most of what a laptop does and none of it is
		// interesting, so drop it before it reaches the baseline. The binary
		// itself still gets registered, otherwise a process that only ever talks
		// to a CDN would have no baseline and its first real contact would look
		// like a first contact.
		if f.Hosting {
			c.evaluated[f.Key] = true
			c.store.Remember(proc.Key(), proc.Name, "", now)
			c.store.Suppress(1)
			continue
		}

		remoteKey := f.RemoteIP + ":" + itoa(f.RemotePort) + "/" + strings.ToLower(f.Proto)
		// known has to mean outbound history. A listener-only baseline row says
		// nothing about that and would downgrade a first contact to
		// NEW_DESTINATION.
		known := c.store.HasOutboundRemote(proc.Key())
		_, seenRemote, firstSeen := c.store.LookupBinary(proc.Key(), remoteKey)
		c.evaluated[f.Key] = true
		emitted := false

		if learning {
			// Warm-up: learn, stay quiet. Alerting on your own first scan is how
			// you teach someone to ignore the tool.
			c.store.Remember(proc.Key(), proc.Name, remoteKey, now)
			continue
		}

		c.store.Remember(proc.Key(), proc.Name, remoteKey, now)

		where := describeRemote(f)
		if unclassified {
			where += " (ASN unresolved)"
		}
		if unclassified && proc.OriginRisk < 40 {
			continue
		}
		switch {
		case !known:
			emitted = true
			sev := SevMedium
			evidence := []string{"first outbound contact from this executable", where}
			if proc.OriginRisk >= 40 {
				sev = SevHigh
			}
			evidence = append(evidence, proc.OriginWhy...)
			c.report(Finding{
				ID: shortID("first", proc.GUID, remoteKey), Kind: KindFirstNetwork,
				Severity: sev, ProcessGUID: proc.GUID, ProcessName: proc.Name, FlowKey: f.Key,
				Title:    "First ever outbound connection: " + proc.Name,
				Evidence: evidence, FirstSeen: now, LastSeen: now, Count: 1,
			}, proc)
		case !seenRemote:
			emitted = true
			sev := SevLow
			if proc.OriginRisk >= 40 {
				sev = SevMedium
			}
			c.report(Finding{
				ID: shortID("new", proc.GUID, remoteKey), Kind: KindNewRemote,
				Severity: sev, ProcessGUID: proc.GUID, ProcessName: proc.Name, FlowKey: f.Key,
				Title:     "New destination for " + proc.Name + ": " + where,
				Evidence:  []string{"baseline for this executable goes back to " + firstSeen.Format(time.RFC3339), where},
				FirstSeen: now, LastSeen: now, Count: 1,
			}, proc)
		}

		// Origin risk alone is not a finding. Origin risk plus a fresh external
		// contact is, and it is announced once per process.
		if proc.OriginRisk >= 40 {
			c.report(Finding{
				ID: shortID("origin", proc.GUID), Kind: KindRiskyOrigin,
				Severity: SevMedium, ProcessGUID: proc.GUID, ProcessName: proc.Name,
				Title:     "Risky origin went out: " + proc.Name,
				Evidence:  append([]string{"connected to " + where}, proc.OriginWhy...),
				FirstSeen: now, LastSeen: now, Count: 1,
			}, proc)
		}

		// Only genuinely new destinations count here. Eight sockets to remotes
		// the baseline already knows is a browser being a browser.
		if emitted {
			c.fanout[proc.GUID] = append(c.fanout[proc.GUID], now)
			recent := 0
			for _, t := range c.fanout[proc.GUID] {
				if now.Sub(t) <= time.Minute {
					recent++
				}
			}
			if recent >= 8 {
				c.report(Finding{
					ID: shortID("fanout", proc.GUID), Kind: KindFanout,
					Severity:    SevMedium,
					ProcessGUID: proc.GUID, ProcessName: proc.Name,
					Title:     "Fan-out: " + proc.Name + " reached " + itoa(recent) + " new destinations in 60s",
					Evidence:  []string{itoa(recent) + " first-time remote endpoints within one minute"},
					FirstSeen: now, LastSeen: now, Count: recent,
				}, proc)
			}
		}
	}
}

// The store dedupes by finding id, so a second sighting only bumps the count.
// Only genuinely new findings reach stdout.
func (c *Collector) report(f Finding, proc Process) {
	if c.store.AddFinding(f) && c.OnFinding != nil {
		c.OnFinding(f)
	}
}

func flowKey(guid, ip string, port int, proto string) string {
	return guid + "|" + ip + ":" + itoa(port) + "/" + strings.ToLower(proto)
}

func protoOf(conn psnet.ConnectionStat) string {
	if conn.Type == 1 {
		return "TCP"
	}
	return "UDP"
}

func describeRemote(f *Flow) string {
	parts := []string{f.RemoteIP + ":" + itoa(f.RemotePort)}
	if f.Country != "" {
		parts = append(parts, f.Country)
	}
	if f.Org != "" {
		parts = append(parts, f.Org)
	} else if f.ASN != 0 {
		parts = append(parts, "AS"+itoa(f.ASN))
	}
	return strings.Join(parts, " · ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Scores where a binary lives and how recently it appeared. Platform agnostic on
// purpose: the first version only matched Windows paths and scored zero on
// everything else.
func originRisk(exe, cwd, cmdline string) (int, []string) {
	score := 0
	var why []string
	l := strings.ToLower(exe)
	c := strings.ToLower(cwd)
	m := strings.ToLower(cmdline)
	hay := l + " " + c

	// Prefix or equal, never substring: /tmp as a cwd says as much as /tmp/x7f,
	// and substring matching silently missed the common case.
	tmpHome := []string{"/tmp", "/var/tmp", "/dev/shm", "/run/user", "/private/tmp"}
	if hasDir(l, tmpHome...) || hasDir(c, tmpHome...) ||
		strings.Contains(hay, `\temp\`) || strings.Contains(hay, `\appdata\local\temp`) {
		score += 45
		why = append(why, "runs from a temporary directory")
	}
	if strings.Contains(hay, "/downloads/") || strings.HasSuffix(c, "/downloads") || strings.Contains(hay, `\downloads\`) {
		score += 30
		why = append(why, "runs from a downloads folder")
	}
	if strings.Contains(hay, "node_modules") || strings.Contains(hay, "/.npm/") {
		score += 30
		why = append(why, "runs from a package install directory")
	}
	if strings.Contains(hay, "/.cache/") || strings.Contains(hay, "/cache/") {
		score += 15
		why = append(why, "runs from a cache directory")
	}
	if strings.Contains(c, "(deleted)") {
		score += 10
		why = append(why, "working directory was deleted")
	}
	if exe == "" {
		score += 20
		why = append(why, "executable path unavailable")
	}
	if strings.Contains(m, "-enc ") || strings.Contains(m, " -encodedcommand") {
		score += 20
		why = append(why, "encoded command line")
	}
	// A binary written today that is already talking to the network is the most
	// useful signal there is without root.
	if exe != "" {
		if st, err := os.Stat(exe); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
			score += 20
			why = append(why, "binary modified in the last 24h")
		}
	}
	if score > 100 {
		score = 100
	}
	return score, why
}

var suspiciousPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|k)?sh\b`), "pipes a download straight into a shell"},
	{regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|-D)\b`), "decodes base64 inline"},
	{regexp.MustCompile(`(?i)/dev/tcp/`), "opens a raw shell socket via /dev/tcp"},
	{regexp.MustCompile(`(?i)\bnc\b[^|]*\s-[a-z]*e[a-z]*\s`), "netcat with a command payload"},
	{regexp.MustCompile(`(?i)\b(python[0-9.]*|perl|ruby|node)\s+-[ce]\b.*(socket|exec|system|eval|child_process)`), "runs an inline script that opens a socket"},
	{regexp.MustCompile(`(?i)\b(invoke-expression|iex)\b`), "PowerShell Invoke-Expression"},
	{regexp.MustCompile(`(?i)\bchmod\s+\+x\s+/tmp/`), "makes a temp file executable"},
}

func suspiciousCmdline(cmd string) (string, bool) {
	if cmd == "" {
		return "", false
	}
	for _, p := range suspiciousPatterns {
		if p.re.MatchString(cmd) {
			return p.desc, true
		}
	}
	return "", false
}

// is dir or lives under it, so /opt/tmpx is not a temp directory.
func hasDir(path string, dirs ...string) bool {
	for _, d := range dirs {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// ParseIP returns nil for an address we could not read, and nil is not
// loopback, which is the answer we want there.
func isLoopbackAddr(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
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

// A bound socket with no peer is a listener, but only for TCP. An unconnected
// UDP socket looks the same and is usually a client that has not sent yet.
func isListener(conn psnet.ConnectionStat) bool {
	if conn.Status == "LISTEN" {
		return true
	}
	return conn.Type == 1 && conn.Raddr.IP == "" && conn.Raddr.Port == 0 && conn.Laddr.Port != 0
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
				// A full disk should not stop the watcher. What is on disk is still
				// the last good baseline and the next tick tries again.
				fmt.Printf("saving baseline: %v\n", err)
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
