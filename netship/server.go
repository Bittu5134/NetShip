package netship

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed all:public
var publicFS embed.FS

// Printed to stdout as findings arrive, so a terminal left open next to the
// dashboard still shows that something happened.
func PrintFinding(f Finding) {
	color := "\033[90m"
	switch f.Severity {
	case SevHigh:
		color = "\033[31m"
	case SevMedium:
		color = "\033[33m"
	case SevLow:
		color = "\033[36m"
	}
	fmt.Printf("%s[%s]\033[0m %s\n", color, strings.ToUpper(f.Severity.String()), f.Title)
}

// App is one store, one optional watcher and a demo store the dashboard can
// switch into. main owns the config and the signal context.
type App struct {
	store    *Store
	enr      *Enricher
	interval time.Duration
	learning time.Duration
	enrich   bool

	mu         sync.Mutex
	baseCtx    context.Context
	cancel     context.CancelFunc
	running    bool
	runStarted time.Time
	gen        int // a stale watcher goroutine must not clear a newer one's state

	demoDir string
	demo    *Store
	demoOn  bool
}

func NewApp(store *Store, enr *Enricher, ctx context.Context, interval, learning time.Duration, enrich bool) *App {
	return &App{
		store:    store,
		enr:      enr,
		baseCtx:  ctx,
		interval: interval,
		learning: learning,
		enrich:   enrich,
	}
}

func (a *App) start() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running || a.demoOn {
		return false
	}
	ctx, cancel := context.WithCancel(a.baseCtx)
	a.cancel = cancel
	a.gen++
	gen := a.gen
	a.running = true
	a.runStarted = time.Now()

	col := NewCollector(a.store, a.enr, a.interval, a.learning)
	col.OnFinding = PrintFinding
	go func() {
		// start -> stop -> start leaves the old goroutine's final save racing
		// the new collector. Without the generation check the stale one clears
		// running and a third watcher gets to spawn.
		err := col.Run(ctx)
		if err != nil {
			fmt.Printf("watcher stopped: %v\n", err)
		}
		cancel()
		a.mu.Lock()
		if a.gen == gen {
			a.running = false
		}
		a.mu.Unlock()
	}()
	return true
}

func (a *App) stop() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running || a.cancel == nil {
		return false
	}
	a.cancel()
	a.running = false
	return true
}

// The demo gets a throwaway directory so it can never be confused with this
// machine's baseline. Seeding happens under a.mu because two concurrent
// /api/state calls would otherwise both seed, which leaks a temp dir.
func (a *App) demoStore() *Store {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.demo == nil {
		dir, err := os.MkdirTemp("", "netship-demo-")
		if err != nil {
			return nil
		}
		s, err := OpenStore(dir)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil
		}
		SeedDemo(s)
		a.demoDir = dir
		a.demo = s
	}
	return a.demo
}

func (a *App) exitDemo() {
	a.mu.Lock()
	a.demoOn = false
	dir := a.demoDir
	a.demoDir = ""
	a.demo = nil
	a.mu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

func (a *App) status() (running, learning, demo bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.demoOn {
		return false, false, true
	}
	return a.running, a.running && time.Since(a.runStarted) < a.learning, false
}

func (a *App) Serve(ln net.Listener) error {
	sub, err := fs.Sub(publicFS, "public")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/state", a.handleState)
	mux.HandleFunc("/api/scan/start", a.handleStart)
	mux.HandleFunc("/api/scan/stop", a.handleStop)
	mux.HandleFunc("/api/demo/start", a.handleDemoStart)
	mux.HandleFunc("/api/demo/stop", a.handleDemoStop)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-a.baseCtx.Done()
		_ = srv.Close()
	}()

	a.start()
	return srv.Serve(ln)
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	running, learning, demo := a.status()

	if demo {
		ds := a.demoStore()
		if ds == nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot build demo data"})
			return
		}
		snap := ds.Snapshot(time.Now(), false, false)
		snap.Demo = true
		snap.Stats.Lookups = 0
		writeJSON(w, http.StatusOK, snap)
		return
	}

	snap := a.store.Snapshot(time.Now(), learning, a.enrich)
	snap.Running = running
	snap.Stats.Lookups = a.enr.Lookups()
	writeJSON(w, http.StatusOK, snap)
}

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.start() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
		return
	}
	writeJSON(w, http.StatusConflict, map[string]string{"error": "watcher is already running, or demo mode is on"})
}

func (a *App) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.stop() {
		_ = a.store.Save()
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
		return
	}
	writeJSON(w, http.StatusConflict, map[string]string{"error": "watcher is not running"})
}

func (a *App) handleDemoStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.stop()
	a.mu.Lock()
	a.demoOn = true
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "demo"})
}

func (a *App) handleDemoStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.exitDemo()
	// Leaving the demo leaves the watcher stopped on purpose: whether this
	// machine gets inspected again is the user's call.
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
