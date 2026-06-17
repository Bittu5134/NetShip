package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

var (
	SessionDataDir  string
	NetworkLog      = "network.jsonl"
	ProcessLog      = "processes.jsonl"
	ChildLog        = "children.jsonl"
	GeoLog          = "geolocation.jsonl"
	HashLog         = "threat_hashes.jsonl"
	MaliciousDbFile = "malicious_hashes.txt"
)

type LeanConnectionMeta struct {
	ProcessGuid     string `json:"process_guid"`
	PID             int32  `json:"pid"`
	ProtocolType    string `json:"protocol_type"`
	IPVersion       string `json:"ip_version"`
	LocalIP         string `json:"local_ip"`
	LocalPort       uint32 `json:"local_port"`
	RemoteIP        string `json:"remote_ip,omitempty"`
	RemotePort      uint32 `json:"remote_port,omitempty"`
	Direction       string `json:"direction"`
	Status          string `json:"status"`
	IsLoopback      bool   `json:"is_loopback"`
	IsInternalAgent bool   `json:"is_internal_agent"`
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

type ChildProcessEvent struct {
	Timestamp         string `json:"timestamp"`
	ParentProcessGuid string `json:"parent_process_guid"`
	ChildProcessGuid  string `json:"child_process_guid"`
	ChildPID          int32  `json:"child_pid"`
	ChildName         string `json:"child_name"`
}

type GeoCacheData struct {
	Timestamp   string `json:"timestamp"`
	IP          string `json:"ip"`
	PID         int32  `json:"pid"`
	ProcessGuid string `json:"process_guid"`
	Country     string `json:"country"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
}

type HashAuditData struct {
	Timestamp   string `json:"timestamp"`
	ProcessGuid string `json:"process_guid"`
	FileName    string `json:"file_name"`
	SHA256      string `json:"sha256"`
	Status      string `json:"status"`
}

// Thread-safe isolation caches
var socketStateCache = make(map[string]LeanConnectionMeta)
var processGuidRegistry = make(map[int32]string)
var pidReferenceCounter = make(map[int32]int)
var sysHostname = "unknown-host"
var fileWriteLock sync.Mutex

var geoCache = make(map[string]GeoCacheData)
var geoCacheLock sync.RWMutex

var maliciousBlacklist = make(map[string]bool)
var blacklistLock sync.RWMutex

var loggedHashes = make(map[string]bool)
var hashCacheLock sync.Mutex

var loggedRelationships = make(map[string]bool)
var childCacheLock sync.Mutex

var activeProcessMemRegistry = make(map[string]*ProcessRegistryData)
var memRegistryLock sync.Mutex

func GenerateProcessGuid(pid int32, createTime int64) string {
	hashInput := fmt.Sprintf("%s-%d-%d", sysHostname, pid, createTime)
	sum := sha256.Sum256([]byte(hashInput))
	return fmt.Sprintf("%x", sum)[:24]
}

func WriteEvent(filename string, event any) {
	fileWriteLock.Lock()
	defer fileWriteLock.Unlock()

	if err := os.MkdirAll(SessionDataDir, 0755); err != nil {
		return
	}
	fullPath := filepath.Join(SessionDataDir, filename)
	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return
	}
	defer file.Close()

	_ = json.NewEncoder(file).Encode(event)
}

func DownloadMaliciousDatabase(dbPath string) error {
	if _, err := os.Stat(dbPath); err == nil {
		return nil
	}

	fmt.Println("📥 [ANTIVIRUS DB] Local threat signatures missing. Syncing from remote repository...")
	url := "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt"
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("network database sync mismatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server target dropped payload with status: %s", resp.Status)
	}

	out, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed creating threat signature database: %w", err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed committing signature streams: %w", err)
	}

	fmt.Println("✨ [ANTIVIRUS DB] Threat signature asset downloaded successfully.")
	return nil
}

func AuditFileHash(procGuid string, filePath string) {
	if filePath == "" || filePath == "ACCESS_DENIED" {
		return
	}

	hashCacheLock.Lock()
	if loggedHashes[procGuid] {
		hashCacheLock.Unlock()
		return
	}
	loggedHashes[procGuid] = true
	hashCacheLock.Unlock()

	go func() {
		file, err := os.Open(filePath)
		if err != nil {
			return
		}
		defer file.Close()

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			return
		}

		shaSignature := fmt.Sprintf("%x", hasher.Sum(nil))
		fName := filepath.Base(filePath)

		hashLogData := HashAuditData{
			Timestamp:   time.Now().Format(time.RFC3339),
			ProcessGuid: procGuid,
			FileName:    fName,
			SHA256:      shaSignature,
			Status:      "CLEAN",
		}

		blacklistLock.RLock()
		isMalicious := maliciousBlacklist[shaSignature]
		blacklistLock.RUnlock()

		if isMalicious {
			hashLogData.Status = "MALICIOUS"
			WriteEvent(HashLog, hashLogData)

			memRegistryLock.Lock()
			if procData, exists := activeProcessMemRegistry[procGuid]; exists {
				procData.ThreatFlags = append(procData.ThreatFlags, "KNOWN_MALWARE_HASH_MATCH (LOCAL_DB)")
				WriteEvent(ProcessLog, UnifiedLogEvent{
					Timestamp: time.Now().Format(time.RFC3339),
					Action:    "THREAT_ALERT",
					Process:   procData,
				})
			}
			memRegistryLock.Unlock()
			fmt.Printf("🚨 [ANTIVIRUS] LOCAL THREAT MATCH! %s matched signature footprint!\n", fName)
			return
		}

		WriteEvent(HashLog, hashLogData)
	}()
}

func AuditChildProcesses(parentPid int32, parentGuid string) {
	p, err := process.NewProcess(parentPid)
	if err != nil {
		return
	}

	children, err := p.Children()
	if err != nil {
		return
	}

	for _, child := range children {
		childPid := child.Pid
		childName, _ := child.Name()
		cTime, _ := child.CreateTime()

		if childName == "" {
			childName = "Transient Subprocess / Short Lifespan Context"
		}

		childGuid := GenerateProcessGuid(childPid, cTime)
		relationshipKey := fmt.Sprintf("%s->%s", parentGuid, childGuid)

		childCacheLock.Lock()
		if loggedRelationships[relationshipKey] {
			childCacheLock.Unlock()
			continue
		}
		loggedRelationships[relationshipKey] = true
		childCacheLock.Unlock()

		childEvent := ChildProcessEvent{
			Timestamp:         time.Now().Format(time.RFC3339),
			ParentProcessGuid: parentGuid,
			ChildProcessGuid:  childGuid,
			ChildPID:          childPid,
			ChildName:         childName,
		}
		WriteEvent(ChildLog, childEvent)
	}
}

func GeolocateRemoteIP(ip string, pid int32, guid string) {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return
	}

	normalizedIP := strings.ToLower(ip)

	geoCacheLock.RLock()
	_, exists := geoCache[normalizedIP]
	geoCacheLock.RUnlock()
	if exists {
		return
	}

	go func() {
		url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp", normalizedIP)
		resp, err := http.Get(url)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var result struct {
			Status  string `json:"status"`
			Country string `json:"country"`
			City    string `json:"city"`
			ISP     string `json:"isp"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Status == "success" {
			geoData := GeoCacheData{
				Timestamp:   time.Now().Format(time.RFC3339),
				IP:          normalizedIP,
				PID:         pid,
				ProcessGuid: guid,
				Country:     result.Country,
				City:        result.City,
				ISP:         result.ISP,
			}

			geoCacheLock.Lock()
			geoCache[normalizedIP] = geoData
			geoCacheLock.Unlock()

			WriteEvent(GeoLog, geoData)
		}
	}()
}

func AnalyzeSocket(conn net.ConnectionStat, guid string) LeanConnectionMeta {
	meta := LeanConnectionMeta{
		ProcessGuid:     guid,
		PID:             conn.Pid,
		LocalIP:         conn.Laddr.IP,
		LocalPort:       conn.Laddr.Port,
		RemoteIP:        conn.Raddr.IP,
		RemotePort:      conn.Raddr.Port,
		Status:          conn.Status,
		IsInternalAgent: conn.Pid == int32(os.Getpid()),
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

		memRegistryLock.Lock()
		activeProcessMemRegistry[guid] = &procData
		memRegistryLock.Unlock()

		WriteEvent(ProcessLog, UnifiedLogEvent{
			Timestamp: time.Now().Format(time.RFC3339),
			Action:    "PROC_START",
			Process:   &procData,
		})

		AuditFileHash(guid, path)
	}()

	return guid
}

func StartBackgroundService() {
	isInitialRun := true
	if name, err := os.Hostname(); err == nil {
		sysHostname = name
	}

	sessionTimeToken := time.Now().Format("20060102_150405")
	SessionDataDir = filepath.Join("data", sessionTimeToken)

	if err := DownloadMaliciousDatabase(MaliciousDbFile); err != nil {
		fmt.Printf("⚠️  [ANTIVIRUS DB] Automated download failure: %v\n", err)
	}

	if dbFile, err := os.Open(MaliciousDbFile); err == nil {
		scanner := bufio.NewScanner(dbFile)
		dbCount := 0
		blacklistLock.Lock()
		for scanner.Scan() {
			hashLine := strings.TrimSpace(scanner.Text())
			if hashLine != "" && !strings.HasPrefix(hashLine, "#") {
				maliciousBlacklist[strings.ToLower(hashLine)] = true
				dbCount++
			}
		}
		blacklistLock.Unlock()
		dbFile.Close()
		fmt.Printf("📦 [ANTIVIRUS DB] Loaded %d signature records out of system workspace.\n", dbCount)
	}

	for {
		connections, err := net.Connections("all")
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}

		aliveNow := make(map[string]bool)
		myPID := int32(os.Getpid())

		for _, conn := range connections {
			if conn.Pid == myPID {
				continue
			}

			guid := LazyRegisterProcess(conn.Pid)
			meta := AnalyzeSocket(conn, guid)
			socketKey := fmt.Sprintf("%s-%s:%d-%s:%d", meta.ProtocolType, meta.LocalIP, meta.LocalPort, meta.RemoteIP, meta.RemotePort)

			aliveNow[socketKey] = true

			if meta.Direction == "OUTBOUND" && !meta.IsLoopback {
				GeolocateRemoteIP(meta.RemoteIP, conn.Pid, guid)
			}
			if conn.Pid > 0 {
				AuditChildProcesses(conn.Pid, guid)
			}

			if _, alreadyTracked := socketStateCache[socketKey]; !alreadyTracked {
				socketStateCache[socketKey] = meta
				pidReferenceCounter[conn.Pid]++

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
			if strings.Contains(trackedKey, "->") {
				continue
			}

			if !aliveNow[trackedKey] {
				if !isInitialRun {
					WriteEvent(NetworkLog, UnifiedLogEvent{
						Timestamp:  time.Now().Format(time.RFC3339),
						Action:     "CLOSED",
						Connection: &trackedState,
					})
				}

				pidReferenceCounter[trackedState.PID]--
				if pidReferenceCounter[trackedState.PID] <= 0 {
					delete(processGuidRegistry, trackedState.PID)
					delete(pidReferenceCounter, trackedState.PID)

					memRegistryLock.Lock()
					delete(activeProcessMemRegistry, trackedState.ProcessGuid)
					memRegistryLock.Unlock()
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