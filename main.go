package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

// CompleteRawProcessInfo stores comprehensive static metadata about an executable footprint
type CompleteRawProcessInfo struct {
	PID        int32    `json:"pid"`
	Name       string   `json:"name"`
	Path       string   `json:"path,omitempty"`
	CmdLine    string   `json:"cmdline,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Username   string   `json:"username,omitempty"`
	Status     []string `json:"status,omitempty"`
	CreateTime int64    `json:"create_time,omitempty"`
}

// EnrichedConnection maps raw network sockets to highly readable security structures
type EnrichedConnection struct {
	net.ConnectionStat
	ProtocolType string `json:"protocol_type"` // "TCP" or "UDP"
	IPVersion    string `json:"ip_version"`    // "IPv4" or "IPv6"
	Direction    string `json:"direction"`     // "INBOUND" or "OUTBOUND"
	IsLoopback   bool   `json:"is_loopback"`   // true if internal loopback traffic
}

// LogEvent represents our lean, relational logging schema envelope
type LogEvent struct {
	Timestamp   string                 `json:"timestamp"`
	Action      string                 `json:"action"` // "PROC_START", "OPEN", "CLOSED"
	ThreatFlags []string               `json:"threat_flags,omitempty"`
	Connection  *EnrichedConnection    `json:"connection,omitempty"`
	Process     CompleteRawProcessInfo `json:"process"`
}

// Global state machine tracking caches
var masterData = make(map[string]EnrichedConnection)
var knownPIDs = make(map[int32]bool)

// LogToJsonl writes a single flat string record directly to our database target file
func LogToJsonl(filename string, event LogEvent) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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

// EnrichAndAnalyze interprets protocol identifiers from the raw socket connection
func EnrichAndAnalyze(conn net.ConnectionStat) EnrichedConnection {
	enriched := EnrichedConnection{ConnectionStat: conn}

	// 1. Normalize Protocols
	if conn.Type == 1 {
		enriched.ProtocolType = "TCP"
	} else if conn.Type == 2 {
		enriched.ProtocolType = "UDP"
	}

	// 2. Identify IP Version
	if conn.Family == 2 {
		enriched.IPVersion = "IPv4"
	} else if conn.Family == 23 {
		enriched.IPVersion = "IPv6"
	}

	// 3. Evaluate Connection Direction
	if conn.Status == "LISTEN" || (conn.Raddr.IP == "" && conn.Raddr.Port == 0) {
		enriched.Direction = "INBOUND"
	} else {
		enriched.Direction = "OUTBOUND"
	}

	// 4. Identify Loopback Internal Noise
	if conn.Laddr.IP == "127.0.0.1" || conn.Laddr.IP == "::1" || conn.Raddr.IP == "127.0.0.1" || conn.Raddr.IP == "::1" {
		enriched.IsLoopback = true
	}

	return enriched
}

// AuditThreatIndicators inspects the host metadata block for risk signatures
func AuditThreatIndicators(proc CompleteRawProcessInfo) []string {
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
	fmt.Println("=== NetShip Relational Security Daemon Online ===")

	for {
		connections, err := net.Connections("all")
		if err != nil {
			fmt.Println("Error retrieving connections:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		aliveNow := make(map[string]bool)

		for _, conn := range connections {
			enriched := EnrichAndAnalyze(conn)
			socketKey := fmt.Sprintf("%s-%s:%d", enriched.ProtocolType, enriched.Laddr.IP, enriched.Laddr.Port)
			aliveNow[socketKey] = true

			_, alreadyTracked := masterData[socketKey]

			if !alreadyTracked {
				var procDetails CompleteRawProcessInfo
				procDetails.PID = conn.Pid

				// Core Process Registration Phase
				if conn.Pid > 0 {
					p, err := process.NewProcess(conn.Pid)
					if err == nil {
						procDetails.Name, _ = p.Name()
						procDetails.Path, _ = p.Exe()
						procDetails.CmdLine, _ = p.Cmdline()
						procDetails.Cwd, _ = p.Cwd()
						procDetails.Username, _ = p.Username()
						procDetails.Status, _ = p.Status()
						procDetails.CreateTime, _ = p.CreateTime()

						// FIRST-TIME DISCOVERY: Process Identity Tracing
						if !knownPIDs[conn.Pid] {
							knownPIDs[conn.Pid] = true
							threats := AuditThreatIndicators(procDetails)

							// Log the full process identity data ONCE
							LogToJsonl("netship.jsonl", LogEvent{
								Timestamp:   time.Now().Format(time.RFC3339),
								Action:      "PROC_START",
								ThreatFlags: threats,
								Process:     procDetails,
							})
							fmt.Printf("🏷️  [PROC_START] Captured Identity for PID %d (%s)\n", conn.Pid, procDetails.Name)
						}
					} else {
						procDetails.Name = "SYSTEM / Access Denied"
						procDetails.Path = "ACCESS_DENIED"
					}
				} else if conn.Pid == 0 {
					procDetails.Name = "Idle Kernel Context"
				}

				// Cache our local socket reference mapping
				masterData[socketKey] = enriched

				// Log network exposures dynamically only when PAST the initial boot baseline scan
				if !isInitialRun {
					// RELATIONAL OPTIMIZATION: We drop all deep string assets here!
					leanProc := CompleteRawProcessInfo{
						PID:  procDetails.PID,
						Name: procDetails.Name,
					}

					LogToJsonl("netship.jsonl", LogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "OPEN",
						Connection: &enriched,
						Process:    leanProc,
					})
					fmt.Printf("🆕 [SOCKET OPENED] %s mapped to PID %d\n", socketKey, leanProc.PID)
				}
			}
		}

		// Differential Deletion Pass for drops
		for trackedKey, trackedState := range masterData {
			if !aliveNow[trackedKey] {
				if !isInitialRun {
					// Relational Optimization rule applied to closure logging fields too
					leanProc := CompleteRawProcessInfo{
						PID:  trackedState.Pid,
						Name: "Detached",
					}

					LogToJsonl("netship.jsonl", LogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "CLOSED",
						Connection: &trackedState,
						Process:    leanProc,
					})
					fmt.Printf("🛑 [SOCKET CLOSED] %s dropped cleanly\n", trackedKey)
				}
				delete(masterData, trackedKey)
			}
		}

		if isInitialRun {
			isInitialRun = false
			fmt.Println("=== Initial System Baseline Saved. Monitoring Network Transitions... ===")
		}

		time.Sleep(3 * time.Second)
	}
}