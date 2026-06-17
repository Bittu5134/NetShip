package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

const (
	DataDir    = "data"
	NetworkLog = "network.jsonl"
	ProcessLog = "processes.jsonl"
)

type LeanConnectionMeta struct {
	ProcessGuid  string `json:"process_guid"`
	PID          int32  `json:"pid"`
	ProtocolType string `json:"protocol_type"`
	IPVersion    string `json:"ip_version"`
	LocalIP      string `json:"local_ip"`
	LocalPort    uint32 `json:"local_port"`
	RemoteIP     string `json:"remote_ip,omitempty"`
	RemotePort   uint32 `json:"remote_port,omitempty"`
	Direction    string `json:"direction"`
	Status       string `json:"status"`
	IsLoopback   bool   `json:"is_loopback"`
}

type ProcessRegistryData struct {
	ProcessGuid string   `json:"process_guid"`
	PID         int32    `json:"pid"`
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	CmdLine     string   `json:"cmdline,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	Username    string   `json:"username,omitempty"`
	CreateTime  int64    `json:"create_time,omitempty"`
	ThreatFlags []string `json:"threat_flags,omitempty"`
}

type UnifiedLogEvent struct {
	Timestamp  string               `json:"timestamp"`
	Action     string               `json:"action"` 
	Connection *LeanConnectionMeta  `json:"connection,omitempty"`
	Process    *ProcessRegistryData `json:"process,omitempty"`
}

// Global Maps and Locks
var socketStateCache = make(map[string]LeanConnectionMeta)
var processGuidRegistry = make(map[int32]string)
var pidReferenceCounter = make(map[int32]int) // FIXED: Moved to global scope
var sysHostname = "unknown-host"
var fileWriteLock sync.Mutex                  // FIXED: Added Mutex for thread safety

func GenerateProcessGuid(pid int32, createTime int64) string {
	hashInput := fmt.Sprintf("%s-%d-%d", sysHostname, pid, createTime)
	sum := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", sum)[:24]
}

func WriteEvent(filename string, event UnifiedLogEvent) {
	// FIXED: Lock the file write operation so Goroutines don't crash the file system
	fileWriteLock.Lock()
	defer fileWriteLock.Unlock()

	if err := os.MkdirAll(DataDir, 0755); err != nil {
		return
	}
	fullPath := filepath.Join(DataDir, filename)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()

	_ = json.NewEncoder(file).Encode(event)
}

func AnalyzeSocket(conn net.ConnectionStat, guid string) LeanConnectionMeta {
	meta := LeanConnectionMeta{
		ProcessGuid: guid,
		PID:         conn.Pid,
		LocalIP:     conn.Laddr.IP,
		LocalPort:   conn.Laddr.Port,
		RemoteIP:    conn.Raddr.IP,
		RemotePort:  conn.Raddr.Port,
		Status:      conn.Status,
	}

	if conn.Type == 1 {
		meta.ProtocolType = "TCP"
	} else {
		meta.ProtocolType = "UDP"
	}

	if conn.Family == 2 {
		meta.IPVersion = "IPv4"
	} else {
		meta.IPVersion = "IPv6"
	}

	if conn.Status == "LISTEN" || (conn.Raddr.IP == "" && conn.Raddr.Port == 0) {
		meta.Direction = "INBOUND"
	} else {
		meta.Direction = "OUTBOUND"
	}

	if conn.Laddr.IP == "127.0.0.1" || conn.Laddr.IP == "::1" || conn.Raddr.IP == "127.0.0.1" || conn.Raddr.IP == "::1" {
		meta.IsLoopback = true
	}

	return meta
}

func EvaluateThreats(path, username string) []string {
	var flags []string
	lowerPath := strings.ToLower(path)

	if strings.Contains(lowerPath, "\\appdata\\local\\temp") || strings.Contains(lowerPath, "\\windows\\temp") {
		flags = append(flags, "EXEC_FROM_TEMP_PATH")
	}
	if strings.Contains(lowerPath, "\\users\\") && strings.Contains(lowerPath, "\\downloads\\") {
		flags = append(flags, "EXEC_FROM_DOWNLOADS_FOLDER")
	}
	if username == "NT AUTHORITY\\SYSTEM" {
		if strings.Contains(lowerPath, "chrome.exe") || strings.Contains(lowerPath, "brave.exe") || strings.Contains(lowerPath, "music") {
			flags = append(flags, "SUSPICIOUS_SYSTEM_PRIVILEGE_MISMATCH")
		}
	}
	return flags
}

func LazyRegisterProcess(pid int32) string {
	if pid <= 0 {
		return "00000000-0000-0000-0000-000000000000"
	}
	if guid, exists := processGuidRegistry[pid]; exists {
		return guid
	}

	p, err := process.NewProcess(pid)
	if err != nil {
		processGuidRegistry[pid] = "SYSTEM-ACCESS-DENIED-TOKEN"
		return "SYSTEM-ACCESS-DENIED-TOKEN"
	}

	name, _ := p.Name()
	path, _ := p.Exe()
	cmd, _ := p.Cmdline()
	cwd, _ := p.Cwd()
	user, _ := p.Username()
	cTime, _ := p.CreateTime()

	guid := GenerateProcessGuid(pid, cTime)
	processGuidRegistry[pid] = guid

	go func() {
		procData := ProcessRegistryData{
			ProcessGuid: guid,
			PID:         pid,
			Name:        name,
			Path:        path,
			CmdLine:     cmd,
			Cwd:         cwd,
			Username:    user,
			CreateTime:  cTime,
			ThreatFlags: EvaluateThreats(path, user),
		}

		WriteEvent(ProcessLog, UnifiedLogEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			Action:    "PROC_START",
			Process:   &procData,
		})
	}()

	return guid
}

func StartBackgroundService() {
	isInitialRun := true
	if name, err := os.Hostname(); err == nil {
		sysHostname = name
	}

	fmt.Println("=== NetShip Optimized Security Engine Running ===")

	for {
		connections, err := net.Connections("all")
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		aliveNow := make(map[string]bool)

		for _, conn := range connections {
			guid := LazyRegisterProcess(conn.Pid)
			meta := AnalyzeSocket(conn, guid)
			socketKey := fmt.Sprintf("%s-%s:%d-%s:%d", meta.ProtocolType, meta.LocalIP, meta.LocalPort, meta.RemoteIP, meta.RemotePort)
			
			aliveNow[socketKey] = true

			if _, alreadyTracked := socketStateCache[socketKey]; !alreadyTracked {
				socketStateCache[socketKey] = meta
				pidReferenceCounter[conn.Pid]++ // FIXED: Increment global counter safely

				if !isInitialRun {
					WriteEvent(NetworkLog, UnifiedLogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "OPEN",
						Connection: &meta,
					})
				}
			}
		}

		for trackedKey, trackedState := range socketStateCache {
			if !aliveNow[trackedKey] {
				if !isInitialRun {
					WriteEvent(NetworkLog, UnifiedLogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "CLOSED",
						Connection: &trackedState,
					})
				}

				// FIXED: Safely decrement. Only wipe data when all sockets are verified dead.
				pidReferenceCounter[trackedState.PID]--
				if pidReferenceCounter[trackedState.PID] <= 0 {
					delete(processGuidRegistry, trackedState.PID)
					delete(pidReferenceCounter, trackedState.PID) // Clear memory
				}

				delete(socketStateCache, trackedKey)
			}
		}

		if isInitialRun {
			isInitialRun = false
			fmt.Println("=== Baseline Completed. Optimized Pipeline Operational ===")
		}

		time.Sleep(2 * time.Second)
	}
}