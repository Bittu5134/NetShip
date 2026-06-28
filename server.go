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
	scanMu  sync.Mutex
	procCmd *exec.Cmd
	running bool
)

func isScanRunning() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	return running
}

func startScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()

	if running {
		return false
	}

	cmd := exec.Command(os.Args[0], "scan")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("Error starting scanner: %v\n", err)
		return false
	}

	procCmd = cmd
	running = true

	go func() {
		if err := procCmd.Wait(); err != nil {
			fmt.Printf("Scanner exited: %v\n", err)
		}
		scanMu.Lock()
		running = false
		procCmd = nil
		scanMu.Unlock()
	}()

	return true
}

func stopScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()

	if !running || procCmd == nil {
		return false
	}

	if err := procCmd.Process.Kill(); err != nil {
		fmt.Printf("Error killing scanner: %v\n", err)
		return false
	}

	running = false
	procCmd = nil
	return true
}

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
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		dir := filepath.Join("data", name)
		started, err := time.Parse("20060102_150405", name)
		if err != nil {
			started = time.Time{}
		}

		netCount := countLines(filepath.Join(dir, "network.jsonl"))
		procCount := countLines(filepath.Join(dir, "processes.jsonl"))
		threatCount := countThreats(filepath.Join(dir, "threat_hashes.jsonl"))

		sessions = append(sessions, SessionSummary{
			ID:           name,
			StartedAt:    started,
			NetworkCount: netCount,
			ProcessCount: procCount,
			ThreatCount:  threatCount,
			HasThreats:   threatCount > 0,
		})
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].StartedAt.After(sessions[j].StartedAt)
	})

	return sessions, nil
}

func countLines(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

func countThreats(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), `"MALICIOUS"`) {
			count++
		}
	}
	return count
}

func readJSONL(path string) ([]json.RawMessage, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []json.RawMessage{}, nil
		}
		return nil, err
	}
	defer file.Close()

	var rows []json.RawMessage
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			rows = append(rows, json.RawMessage(line))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func writeJSON(w http.ResponseWriter, code int, val interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(val); err != nil {
		fmt.Printf("Error writing JSON response: %v\n", err)
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	activeSession := ""
	sessions, _ := listSessions()
	active := isScanRunning()
	if len(sessions) > 0 && active {
		activeSession = sessions[0].ID
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"running":     active,
		"session_dir": activeSession,
	})
}

func handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if startScan() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "started"})
	} else {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Scanner is already running"})
	}
}

func handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if stopScan() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
	} else {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Scanner is not running"})
	}
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := listSessions()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func handleSessionData(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/session/"), "/")
	if len(parts) != 2 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sessionID, fileKey := parts[0], parts[1]
	fileMap := map[string]string{
		"network":  "network.jsonl",
		"process":  "processes.jsonl",
		"children": "children.jsonl",
		"geo":      "geolocation.jsonl",
		"hashes":   "threat_hashes.jsonl",
	}

	fileName, ok := fileMap[fileKey]
	if !ok {
		http.Error(w, "Invalid file key", http.StatusBadRequest)
		return
	}

	if strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	rows, err := readJSONL(filepath.Join("data", sessionID, fileName))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func handleLive(w http.ResponseWriter, r *http.Request) {
	fileKey := strings.TrimPrefix(r.URL.Path, "/api/live/")
	fileMap := map[string]string{
		"network":  "network.jsonl",
		"process":  "processes.jsonl",
		"children": "children.jsonl",
		"geo":      "geolocation.jsonl",
		"hashes":   "threat_hashes.jsonl",
	}

	fileName, ok := fileMap[fileKey]
	if !ok {
		http.Error(w, "Invalid live channel", http.StatusBadRequest)
		return
	}

	sessions, _ := listSessions()
	if len(sessions) == 0 {
		writeJSON(w, http.StatusOK, []json.RawMessage{})
		return
	}

	rows, err := readJSONL(filepath.Join("data", sessions[0].ID, fileName))
	if err != nil {
		writeJSON(w, http.StatusOK, []json.RawMessage{})
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func StartServer(addr string) {
	mux := http.NewServeMux()

	var publicFS http.FileSystem
	if _, err := os.Stat("public"); err == nil {
		fmt.Println("Serving files from local public folder")
		publicFS = http.Dir("public")
	} else {
		fmt.Println("Serving files from binary embedded assets")
		strippedFS, err := fs.Sub(embeddedPublic, "public")
		if err != nil {
			panic(err)
		}
		publicFS = http.FS(strippedFS)
	}

	mux.Handle("/", http.FileServer(publicFS))

	mux.HandleFunc("/datacenters.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		filePath := filepath.Join("resources", "datacenters.json")
		fileBytes, err := os.ReadFile(filePath)
		if err != nil {
			w.Write([]byte("[]"))
			return
		}
		w.Write(fileBytes)
	})

	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/scan/start", handleStartScan)
	mux.HandleFunc("/api/scan/stop", handleStopScan)
	mux.HandleFunc("/api/live/", handleLive)
	mux.HandleFunc("/api/sessions", handleSessions)
	mux.HandleFunc("/api/session/", handleSessionData)

	fmt.Printf("Dashboard portal online at http://localhost%s\n", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}
