package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

func prettyJson(data any) string {
	prettyJSON, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}
	return string(prettyJSON)
}

type ProcessInfo struct {
	PID        int32    `json:"pid"`
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	CmdLine    string   `json:"cmdline"`
	Cwd        string   `json:"cwd"`
	Username   string   `json:"username"`
	Status     []string `json:"status"`
	CreateTime int64    `json:"create_time"`
}

type RawState struct {
	Connection net.ConnectionStat `json:"connection"`
	Process    ProcessInfo        `json:"process"`
}

type LogEvent struct {
	Timestamp string   `json:"timestamp"`
	Action    string   `json:"action"` // "OPEN" or "CLOSE"
	Process   RawState `json:"process"`
}

// LogToJsonl handles opening, formatting, and appending to your log file
func LogToJsonl(filename string, event LogEvent) error {
	// 1. Open the file or create it if it's missing.
	// O_APPEND ensures new entries are typed directly onto the bottom of the file.
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close() // Ensure the system file handle resource releases when done

	// 2. Marshal the struct into a compact, single-line JSON byte array
	// (Do NOT use MarshalIndent here; JSONL require everything on one line!)
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// 3. Write the JSON payload to the file stream
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed writing data bytes: %w", err)
	}

	// 4. CRITICAL: Append the newline token to terminate the line boundary
	_, err = file.WriteString("\n")
	if err != nil {
		return fmt.Errorf("failed writing line terminator: %w", err)
	}

	return nil
}

func main() {
	var masterData = make(map[string]RawState)
	isInitialRun := true
	fmt.Println("=== NetShip Unfiltered Core Daemon Started ===")

	for {
		connections, err := net.Connections("all")
		if err != nil {
			fmt.Println("Error retrieving connections:", err)
			time.Sleep(2 * time.Second)
			continue
		}

		aliveNow := make(map[string]bool)

		for _, conn := range connections {
			// Determine the protocol string based on Socket Type (1=TCP, 2=UDP)
			protoStr := "TCP"
			if conn.Type == 2 {
				protoStr = "UDP"
			}

			// Generate a completely unique identifier for this specific socket connection
			socketKey := fmt.Sprintf("%s-%s:%d", protoStr, conn.Laddr.IP, conn.Laddr.Port)
			aliveNow[socketKey] = true

			_, alreadyTracked := masterData[socketKey]

			if !alreadyTracked {
				var procDetails ProcessInfo
				procDetails.PID = conn.Pid

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
					} else {
						procDetails.Name = "SYSTEM / Unknown"
						procDetails.Path = "ACCESS_DENIED"
					}
				}

				newState := RawState{
					Connection: conn,
					Process:    procDetails,
				}

				masterData[socketKey] = newState

				if isInitialRun {
					fmt.Printf("[INITIAL BASELINE] Socket %s Baseline Captured:\n%s\n\n", socketKey, prettyJson(newState))
				} else {
					fmt.Printf("🆕 [SOCKET OPENED] %s Alert Raw Dump:\n%s\n\n", socketKey, prettyJson(newState))
					LogToJsonl("netship.jsonl", LogEvent{
						Timestamp: time.Now().Format(time.RFC3339),
						Action:    "OPEN",
						Process:   newState,
					})
				}
			}
		}

		// Differential Deletion Pass for closed/dropped sockets
		for trackedKey, trackedState := range masterData {
			if !aliveNow[trackedKey] {
				fmt.Printf("🛑 [SOCKET CLOSED] %s Closure Raw Dump:\n%s\n\n", trackedKey, prettyJson(trackedState))
				delete(masterData, trackedKey)
				LogToJsonl("netship.jsonl", LogEvent{
					Timestamp: time.Now().Format(time.RFC3339),
					Action:    "CLOSED",
					Process:   trackedState,
				})
			}
		}

		if isInitialRun {
			isInitialRun = false
			fmt.Println("=== Initial Baseline Established. Continuously Auditing All Sockets... ===")
		}

		time.Sleep(5 * time.Second)
	}
}
