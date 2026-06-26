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

// Spawns background scan process
func startScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	
	if isTracking {
		return false
	}

	commandArgs := []string{"scan"}
	cmd := exec.Command(os.Args[0], commandArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		fmt.Printf("Error starting background scanner process: %v\n", err)
		return false
	}

	workerCmd = cmd
	isTracking = true

	go func() {
		err = workerCmd.Wait()
		if err != nil {
			fmt.Printf("Scanner process exited with notification: %v\n", err)
		}
		
		scanMu.Lock()
		isTracking = false
		workerCmd = nil
		scanMu.Unlock()
		
		fmt.Println("Background scanner process has terminated.")
	}()

	return true
}

// Terminates background scan process
func stopScan() bool {
	scanMu.Lock()
	defer scanMu.Unlock()
	
	if !isTracking {
		return false
	}
	if workerCmd == nil {
		return false
	}

	err := workerCmd.Process.Kill()
	if err != nil {
		fmt.Printf("Error encountered killing scanner process: %v\n", err)
		return false
	}

	isTracking = false
	workerCmd = nil
	return true
}

// LOG FILE PARSERS

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
			emptySummaryList := []SessionSummary{}
			return emptySummaryList, nil
		}
		return nil, err
	}

	var sessions []SessionSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		
		sessionName := entry.Name()
		dirPath := filepath.Join("data", sessionName)
		startedTime, err := time.Parse("20060102_150405", sessionName)
		if err != nil {
			startedTime = time.Time{}
		}

		netCount := countLines(filepath.Join(dirPath, "network.jsonl"))
		procCount := countLines(filepath.Join(dirPath, "processes.jsonl"))
		threatCount := countThreats(filepath.Join(dirPath, "threat_hashes.jsonl"))

		hasThreats := false
		if threatCount > 0 {
			hasThreats = true
		}

		sessions = append(sessions, SessionSummary{
			ID:           sessionName,
			StartedAt:    startedTime,
			NetworkCount: netCount,
			ProcessCount: procCount,
			ThreatCount:  threatCount,
			HasThreats:   hasThreats,
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
	lineCount := 0
	
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			lineCount = lineCount + 1
		}
	}
	
	return lineCount
}

func countThreats(path string) int {
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	threatCount := 0
	
	for scanner.Scan() {
		text := scanner.Text()
		if strings.Contains(text, `"MALICIOUS"`) {
			threatCount = threatCount + 1
		}
	}
	
	return threatCount
}

func readJSONL(path string) ([]json.RawMessage, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			emptyList := []json.RawMessage{}
			return emptyList, nil
		}
		return nil, err
	}
	defer file.Close()

	var outputRows []json.RawMessage
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		outputRows = append(outputRows, json.RawMessage(line))
	}
	
	err = scanner.Err()
	if err != nil {
		return nil, err
	}
	
	return outputRows, nil
}

// HTTP API HANDLERS

func writeJSONResponse(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	encoder := json.NewEncoder(w)
	err := encoder.Encode(payload)
	if err != nil {
		fmt.Printf("Error writing JSON payload: %v\n", err)
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	activeSessionID := ""
	sessions, _ := listSessions()
	
	runningState := isScanRunning()
	if len(sessions) > 0 && runningState {
		activeSessionID = sessions[0].ID
	}
	
	responseMap := map[string]interface{}{
		"running":     runningState,
		"session_dir": activeSessionID,
	}
	
	writeJSONResponse(w, 200, responseMap)
}

func handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST HTTP Method Required", http.StatusMethodNotAllowed)
		return
	}
	
	started := startScan()
	if started {
		response := map[string]string{"status": "started"}
		writeJSONResponse(w, 200, response)
	} else {
		response := map[string]string{"error": "Scanner process is already running"}
		writeJSONResponse(w, http.StatusConflict, response)
	}
}

func handleStopScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST HTTP Method Required", http.StatusMethodNotAllowed)
		return
	}
	
	stopped := stopScan()
	if stopped {
		response := map[string]string{"status": "stopped"}
		writeJSONResponse(w, 200, response)
	} else {
		response := map[string]string{"error": "Scanner process is not running"}
		writeJSONResponse(w, http.StatusConflict, response)
	}
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := listSessions()
	if err != nil {
		errorResponse := map[string]string{"error": err.Error()}
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse)
		return
	}
	writeJSONResponse(w, 200, sessions)
}

func handleSessionData(w http.ResponseWriter, r *http.Request) {
	requestPath := strings.TrimPrefix(r.URL.Path, "/api/session/")
	pathParts := strings.Split(requestPath, "/")
	
	if len(pathParts) != 2 {
		http.Error(w, "Bad request path format", http.StatusBadRequest)
		return
	}
	
	sessionID := pathParts[0]
	fileKey := pathParts[1]

	fileMap := map[string]string{
		"network":  "network.jsonl",
		"process":  "processes.jsonl",
		"children": "children.jsonl",
		"geo":      "geolocation.jsonl",
		"hashes":   "threat_hashes.jsonl",
	}
	
	fileName, isValidKey := fileMap[fileKey]
	if !isValidKey {
		http.Error(w, "Invalid data file target", http.StatusBadRequest)
		return
	}
	
	if strings.Contains(sessionID, "..") || strings.Contains(sessionID, "/") {
		http.Error(w, "Invalid path query parameters detected", http.StatusBadRequest)
		return
	}

	targetFilePath := filepath.Join("data", sessionID, fileName)
	rows, err := readJSONL(targetFilePath)
	if err != nil {
		errorResponse := map[string]string{"error": err.Error()}
		writeJSONResponse(w, http.StatusInternalServerError, errorResponse)
		return
	}
	
	writeJSONResponse(w, 200, rows)
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
	
	fileName, isValidKey := fileMap[fileKey]
	if !isValidKey {
		http.Error(w, "Invalid live channel target", http.StatusBadRequest)
		return
	}

	sessions, _ := listSessions()
	if len(sessions) == 0 {
		emptyList := []json.RawMessage{}
		writeJSONResponse(w, 200, emptyList)
		return
	}

	targetFilePath := filepath.Join("data", sessions[0].ID, fileName)
	rows, err := readJSONL(targetFilePath)
	if err != nil {
		emptyList := []json.RawMessage{}
		writeJSONResponse(w, 200, emptyList)
		return
	}
	
	writeJSONResponse(w, 200, rows)
}

// SERVER ENTRY POINT

func StartServer(addr string) {
	mux := http.NewServeMux()

	var publicFS http.FileSystem
	_, err := os.Stat("public")
	
	if err == nil {
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
	
	err = http.ListenAndServe(addr, mux)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Server failed to bind: %v\n", err)
		os.Exit(1)
	}
}