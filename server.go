package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed all:public
var embeddedPublic embed.FS

var (
	scanMu     sync.Mutex
	workerCmd  *exec.Cmd
	isTracking bool
)

func isScanRunning() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	return isTracking
}

// startScan spawns the background worker binary as an independent operating system process
func startScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	if isTracking {
		return false
	}

	cmd := exec.Command(os.Args[0], "scan")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting background scanner: %v\n", err)
		return false
	}

	workerCmd = cmd
	isTracking = true

	go func() {
		_ = workerCmd.Wait()
		scanMu.Lock()
		isTracking = false
		workerCmd = nil
		scanMu.Unlock()
		fmt.Println("Background scanner process has terminated.")
	}()

	return true
}

// stopScan safely kills the independent background tracking process
func stopScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	if !isTracking || workerCmd == nil {
		return false
	}

	if err := workerCmd.Process.Kill(); err != nil {
		return false
	}

	isTracking = false
	workerCmd = nil
	return true
}

// ── Log File Parsers ─────────────────────────────────────────────────────────

type SessionSummary struct {
	ID           string    `json:"id"`
	StartedAt    time.Time `json:"started_at"`
	NetworkCount int       `json:"network_count"`
	ProcessCount int       `json:"process_count"`
	ThreatCount  int       `json:"threat_count"`
	HasThreats   bool      `json:"has_threats"`
}

func listSessions() ([]SessionSummary, error) {
	entries, err := os.ReadDir("data")
	if err != nil {
		if os.IsNotExist(err) {
			return []SessionSummary{}, nil
		}
		return nil, err
	}

	var sessions []SessionSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join("data", e.Name())
		t, _ := time.Parse("20060102_150405", e.Name())

		sessions = append(sessions, SessionSummary{
			ID:           e.Name(),
			StartedAt:    t,
			NetworkCount: countLines(filepath.Join(dir, "network.jsonl")),
			ProcessCount: countLines(filepath.Join(dir, "processes.jsonl")),
			ThreatCount:  countThreats(filepath.Join(dir, "threat_hashes.jsonl")),
			HasThreats:   countThreats(filepath.Join(dir, "threat_hashes.jsonl")) > 0,
		})
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartedAt.After(sessions[j].StartedAt)
	})
	return sessions, nil
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			n++
		}
	}
	return n
}

func countThreats(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		if strings.Contains(s.Text(), `"MALICIOUS"`) {
			n++
		}
	}
	return n
}

func readJSONL(path string) ([]json.RawMessage, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []json.RawMessage{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []json.RawMessage
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		out = append(out, json.RawMessage(line))
	}
	return out, s.Err()
}

// ── HTTP API Handlers ────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	activeDir := ""
	sessions, _ := listSessions()
	if len(sessions) > 0 && isScanRunning() {
		activeDir = sessions[0].ID
	}
	jsonResp(w, 200, map[string]any{
		"running":     isScanRunning(),
		"session_dir": activeDir,
	})
}

func handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST endpoints only", 405)
		return
	}
	if startScan() {
		jsonResp(w, 200, map[string]string{"status": "started"})
	} else {
		jsonResp(w, 409, map[string]string{"error": "Scanner is already running"})
	}
}

func handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST endpoints only", 405)
		return
	}
	if stopScan() {
		jsonResp(w, 200, map[string]string{"status": "stopped"})
	} else {
		jsonResp(w, 409, map[string]string{"error": "Scanner is not running"})
	}
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := listSessions()
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, sessions)
}

func handleSessionData(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/session/"), "/")
	if len(parts) != 2 {
		http.Error(w, "bad request path", 400)
		return
	}
	sessionID, fileKey := parts[0], parts[1]

	fileMap := map[string]string{
		"network": "network.jsonl", "process": "processes.jsonl",
		"children": "children.jsonl", "geo": "geolocation.jsonl", "hashes": "threat_hashes.jsonl",
	}
	filename, ok := fileMap[fileKey]
	if !ok || strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.Error(w, "Invalid data file requested", 400)
		return
	}

	path := filepath.Join("data", sessionID, filename)
	rows, err := readJSONL(path)
	if err != nil {
		jsonResp(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, 200, rows)
}

func handleLive(w http.ResponseWriter, r *http.Request) {
	fileKey := strings.TrimPrefix(r.URL.Path, "/api/live/")
	fileMap := map[string]string{
		"network": "network.jsonl", "process": "processes.jsonl",
		"children": "children.jsonl", "geo": "geolocation.jsonl", "hashes": "threat_hashes.jsonl",
	}
	filename, ok := fileMap[fileKey]
	if !ok {
		http.Error(w, "Invalid live channel requested", 400)
		return
	}

	sessions, _ := listSessions()
	if len(sessions) == 0 {
		jsonResp(w, 200, []json.RawMessage{})
		return
	}

	path := filepath.Join("data", sessions[0].ID, filename)
	rows, err := readJSONL(path)
	if err != nil {
		jsonResp(w, 200, []json.RawMessage{})
		return
	}
	jsonResp(w, 200, rows)
}

// ── Server Entry Point ───────────────────────────────────────────────────────

func StartServer(addr string) {
	mux := http.NewServeMux()

	var publicFS http.FileSystem
	if _, err := os.Stat("public"); err == nil {
		fmt.Println("Serving user interface from local ./public directory")
		publicFS = http.Dir("public")
	} else {
		fmt.Println("Serving user interface from binary embedded assets")
		strippedEmbed, err := fs.Sub(embeddedPublic, "public")
		if err != nil {
			panic(err)
		}
		publicFS = http.FS(strippedEmbed)
	}

	// Serve static front-end workspace portal assets
	mux.Handle("/", http.FileServer(publicFS))

	// Data Center File Exposer Route Endpoint
	mux.HandleFunc("/datacenters.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := os.ReadFile(filepath.Join("resources", "datacenters.json"))
		if err != nil {
			w.Write([]byte("[]"))
			return
		}
		w.Write(data)
	})

	// Control Plane endpoints
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/scan/start", handleStartScan)
	mux.HandleFunc("/api/scan/stop", handleStopScan)
	mux.HandleFunc("/api/live/", handleLive)
	mux.HandleFunc("/api/sessions", handleSessions)
	mux.HandleFunc("/api/session/", handleSessionData)

	fmt.Printf("Dashboard portal operational at http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server failure: %v\n", err)
		os.Exit(1)
	}
}