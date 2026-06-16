package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// Data output file target configuration paths
const (
	DataDir    = "data"
	NetworkLog = "network.jsonl"
	ProcessLog = "processes.jsonl"
)

// RawProcessInfo stores comprehensive static metadata about an executable footprint
type RawProcessInfo struct {
	ProcessGuid string   `json:"process_guid,omitempty"`
	PID         int32    `json:"pid"`
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	CmdLine     string   `json:"cmdline,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	Username    string   `json:"username,omitempty"`
	Status      []string `json:"status,omitempty"`
	CreateTime  int64    `json:"create_time,omitempty"`
}

// ProcessMapping maps raw network sockets to readable security structures
type ProcessMapping struct {
	net.ConnectionStat
	ProcessGuid  string `json:"process_guid"`  // Linked relational key mapping
	ProtocolType string `json:"protocol_type"` // "TCP" or "UDP"
	IPVersion    string `json:"ip_version"`    // "IPv4" or "IPv6"
	Direction    string `json:"direction"`     // "INBOUND" or "OUTBOUND"
	IsLoopback   bool   `json:"is_loopback"`   // true if internal loopback traffic
}

// Format for JSONL logs
type LogEvent struct {
	Timestamp   string          `json:"timestamp"`
	Action      string          `json:"action"`
	ThreatFlags []string        `json:"threat_flags,omitempty"`
	Connection  *ProcessMapping `json:"connection,omitempty"`
	Process *RawProcessInfo `json:"process,omitempty"`
}

// Global state machine tracking caches
var masterData = make(map[string]ProcessMapping)
var activeProcessGuids = make(map[int32]string)
var sysHostname = "unknown-host"

// GenerateProcessGuid calculates a unique cryptographic string hash for a process lifetime session
func GenerateProcessGuid(pid int32, createTime int64) string {
	hashInput := fmt.Sprintf("%s-%d-%d", sysHostname, pid, createTime)
	sum := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", sum)[:24]
}

// LogToJsonl handles formatting and writing tracking frames into specific data destinations
func LogToJsonl(filename string, event LogEvent) error {
	if err := os.MkdirAll(DataDir, 0755); err != nil {
		return fmt.Errorf("failed to verify data directory: %w", err)
	}

	fullPath := filepath.Join(DataDir, filename)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	if _, err = file.Write(jsonData); err != nil {
		return fmt.Errorf("failed writing data bytes: %w", err)
	}
	if _, err = file.WriteString("\n"); err != nil {
		return fmt.Errorf("failed writing line terminator: %w", err)
	}
	return nil
}

// ProcessProtocol interprets protocol identifiers from the raw socket connection
func ProcessProtocol(conn net.ConnectionStat, guid string) ProcessMapping {
	enriched := ProcessMapping{ConnectionStat: conn, ProcessGuid: guid}

	switch conn.Type {
	case 1:
		enriched.ProtocolType = "TCP"
	case 2:
		enriched.ProtocolType = "UDP"
	}

	switch conn.Family {
	case 2:
		enriched.IPVersion = "IPv4"
	case 23:
		enriched.IPVersion = "IPv6"
	}

	if conn.Status == "LISTEN" || (conn.Raddr.IP == "" && conn.Raddr.Port == 0) {
		enriched.Direction = "INBOUND"
	} else {
		enriched.Direction = "OUTBOUND"
	}

	if conn.Laddr.IP == "127.0.0.1" || conn.Laddr.IP == "::1" || conn.Raddr.IP == "127.0.0.1" || conn.Raddr.IP == "::1" {
		enriched.IsLoopback = true
	}

	return enriched
}

// AuditThreatIndicators inspects the host metadata block for risk signatures
func AuditThreatIndicators(proc RawProcessInfo) []string {
	var flags []string
	lowerPath := strings.ToLower(proc.Path)

	if strings.Contains(lowerPath, "\\appdata\\local\\temp") || strings.Contains(lowerPath, "\\windows\\temp") {
		flags = append(flags, "EXEC_FROM_TEMP_PATH")
	}
	if strings.Contains(lowerPath, "\\users\\") && strings.Contains(lowerPath, "\\downloads\\") {
		flags = append(flags, "EXEC_FROM_DOWNLOADS_FOLDER")
	}
	if proc.Username == "NT AUTHORITY\\SYSTEM" {
		if strings.Contains(lowerPath, "chrome.exe") || strings.Contains(lowerPath, "brave.exe") || strings.Contains(lowerPath, "music") {
			flags = append(flags, "SUSPICIOUS_SYSTEM_PRIVILEGE_MISMATCH")
		}
	}
	return flags
}

func main() {
	isInitialRun := true
	if name, err := os.Hostname(); err == nil {
		sysHostname = name
	}

	fmt.Println("=== NetShip Daemon Online ===")

	for {
		connections, err := net.Connections("all")
		if err != nil {
			fmt.Println("Error retrieving connections:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		aliveNow := make(map[string]bool)

		for _, conn := range connections {
			procGuid, hasGuid := activeProcessGuids[conn.Pid]

			var procDetails RawProcessInfo
			procDetails.PID = conn.Pid

			if conn.Pid > 0 && !hasGuid {
				p, err := process.NewProcess(conn.Pid)
				if err == nil {
					procDetails.Name, _ = p.Name()
					procDetails.Path, _ = p.Exe()
					procDetails.CmdLine, _ = p.Cmdline()
					procDetails.Cwd, _ = p.Cwd()
					procDetails.Username, _ = p.Username()
					procDetails.Status, _ = p.Status()
					cTime, _ := p.CreateTime()
					procDetails.CreateTime = cTime

					procGuid = GenerateProcessGuid(conn.Pid, cTime)
					procDetails.ProcessGuid = procGuid
					activeProcessGuids[conn.Pid] = procGuid

					threats := AuditThreatIndicators(procDetails)
					LogToJsonl(ProcessLog, LogEvent{
						Timestamp:   time.Now().Format(time.RFC3339),
						Action:      "PROC_START",
						ThreatFlags: threats,
						Process:     &procDetails,
					})
					fmt.Printf("🏷️  [PROC_START] Registered Identity Guid: %s (%s)\n", procGuid, procDetails.Name)
				} else {
					procDetails.Name = "SYSTEM / Access Denied"
					procDetails.Path = "ACCESS_DENIED"
					procGuid = "SYSTEM-ACCESS-DENIED-TOKEN"
					activeProcessGuids[conn.Pid] = procGuid
				}
			} else if conn.Pid == 0 {
				procDetails.Name = "Idle Kernel Context"
				procGuid = "00000000-0000-0000-0000-000000000000"
				activeProcessGuids[conn.Pid] = procGuid
			}

			enriched := ProcessProtocol(conn, procGuid)
			socketKey := fmt.Sprintf("%s-%s:%d", enriched.ProtocolType, enriched.Laddr.IP, enriched.Laddr.Port)
			aliveNow[socketKey] = true

			_, alreadyTracked := masterData[socketKey]

			if !alreadyTracked {
				masterData[socketKey] = enriched

				if !isInitialRun {
					// OPTIMIZATION FIXED: Process property set to nil.
					// The process_guid inside 'connection' handles all relational mapping.
					LogToJsonl(NetworkLog, LogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "OPEN",
						Connection: &enriched,
						Process:    nil,
					})
					fmt.Printf("🆕 [SOCKET OPENED] %s attached via Key %s\n", socketKey, procGuid)
				}
			}
		}

		for trackedKey, trackedState := range masterData {
			if !aliveNow[trackedKey] {
				if !isInitialRun {
					LogToJsonl(NetworkLog, LogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "CLOSED",
						Connection: &trackedState,
						Process:    nil,
					})
					fmt.Printf("🛑 [SOCKET CLOSED] %s released\n", trackedKey)
				}

				delete(activeProcessGuids, trackedState.Pid)
				delete(masterData, trackedKey)
			}
		}

		if isInitialRun {
			isInitialRun = false
			fmt.Println("=== Initial System Baseline Saved. Multi-File Channels Ready. ===")
		}

		time.Sleep(3 * time.Second)
	}
}
