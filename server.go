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

// startScan safely triggers the process fork sequence execution
func startScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	if isTracking {
		return false
	}

	// Fork the background daemon process safely out of the current server thread
	cmd := exec.Command(os.Args[0], "scan")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("⚠️  [SERVER ERROR] Failed to fork standalone worker: %v\n", err)
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
		fmt.Println("📉 [SERVER] External agent telemetry session safely torn down.")
	}()

	return true
}

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

// ── SOC Log File Parsing Helpers ─────────────────────────────────────────────

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
		http.Error(w, "POST only", 405)
		return
	}
	if startScan() {
		jsonResp(w, 200, map[string]string{"status": "started"})
	} else {
		jsonResp(w, 409, map[string]string{"error": "engine session already tracking"})
	}
}

func handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	if stopScan() {
		jsonResp(w, 200, map[string]string{"status": "stopped"})
	} else {
		jsonResp(w, 409, map[string]string{"error": "no active tracking worker instance"})
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
		http.Error(w, "bad path", 400)
		return
	}
	sessionID, fileKey := parts[0], parts[1]

	fileMap := map[string]string{
		"network": "network.jsonl", "process": "processes.jsonl",
		"children": "children.jsonl", "geo": "geolocation.jsonl", "hashes": "threat_hashes.jsonl",
	}
	filename, ok := fileMap[fileKey]
	if !ok || strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.Error(w, "malformed query execution route", 400)
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
		http.Error(w, "unknown asset signature", 400)
		return
	}

	sessions, _ := listSessions()
	if len(sessions) == 0 {
		jsonResp(w, 200, []json.RawMessage{})
		return
	}

	// Telemetry extraction target point (freshest workspace node folder target)
	path := filepath.Join("data", sessions[0].ID, filename)
	rows, err := readJSONL(path)
	if err != nil {
		jsonResp(w, 200, []json.RawMessage{})
		return
	}
	jsonResp(w, 200, rows)
}

func handleUnifiedSearch(w http.ResponseWriter, r *http.Request) {
	query := strings.ToLower(r.URL.Query().Get("q"))
	sessionID := r.URL.Query().Get("session")

	targetDir := ""
	if sessionID != "" {
		targetDir = filepath.Join("data", sessionID)
	} else {
		sessions, _ := listSessions()
		if len(sessions) > 0 {
			targetDir = filepath.Join("data", sessions[0].ID)
		}
	}

	results := map[string][]json.RawMessage{"network": {}, "processes": {}, "hashes": {}}
	if targetDir == "" {
		jsonResp(w, 200, results)
		return
	}

	files := map[string]string{
		"network":   filepath.Join(targetDir, "network.jsonl"),
		"processes": filepath.Join(targetDir, "processes.jsonl"),
		"hashes":    filepath.Join(targetDir, "threat_hashes.jsonl"),
	}

	for key, path := range files {
		rows, err := readJSONL(path)
		if err != nil {
			continue
		}
		for _, row := range rows {
			if strings.Contains(strings.ToLower(string(row)), query) {
				results[key] = append(results[key], row)
			}
		}
	}
	jsonResp(w, 200, results)
}

func StartServer(addr string) {
	mux := http.NewServeMux()

	var publicFS http.FileSystem
	if _, err := os.Stat("public"); err == nil {
		fmt.Println("📁 [SERVER] Sourcing static web assets directly from local workspace disk path.")
		publicFS = http.Dir("public")
	} else {
		fmt.Println("📦 [SERVER] Sourcing static web assets from compiled embedded resource cache mapping space.")
		strippedEmbed, err := fs.Sub(embeddedPublic, "public")
		if err != nil {
			panic(err)
		}
		publicFS = http.FS(strippedEmbed)
	}

	mux.Handle("/", http.FileServer(publicFS))
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/scan/start", handleStartScan)
	mux.HandleFunc("/api/scan/stop", handleStopScan)
	mux.HandleFunc("/api/search", handleUnifiedSearch)
	mux.HandleFunc("/api/live/", handleLive)
	mux.HandleFunc("/api/sessions", handleSessions)
	mux.HandleFunc("/api/session/", handleSessionData)

	fmt.Printf("🌐 [SERVER] Portal node active at http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Fatal operational collapse: %v\n", err)
		os.Exit(1)
	}
}