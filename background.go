package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"
)

var (
	SessionDataDir   string
	NetworkLog       = "network.jsonl"
	ProcessLog       = "processes.jsonl"
	ChildLog         = "children.jsonl"
	GeoLog           = "geolocation.jsonl"
	HashLog          = "threat_hashes.jsonl"
	
	// Resources directory consolidation
	ResourcesDir     = "resources"
	MaliciousDbFile  = filepath.Join(ResourcesDir, "malicious_hashes.txt")
	DataCenterDbFile = filepath.Join(ResourcesDir, "datacenters.json")
	IPv4RangesFile   = filepath.Join(ResourcesDir, "ipv4_merged.txt")
	IPv6RangesFile   = filepath.Join(ResourcesDir, "ipv6_merged.txt")
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
	ThreatScore int      `json:"threat_score"`
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
	Timestamp   string  `json:"timestamp"`
	IP          string  `json:"ip"`
	PID         int32   `json:"pid"`
	ProcessGuid string  `json:"process_guid"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Latitude    float64 `json:"lat"`
	Longitude   float64 `json:"lon"`
}

type HashAuditData struct {
	Timestamp   string `json:"timestamp"`
	ProcessGuid string `json:"process_guid"`
	FileName    string `json:"file_name"`
	SHA256      string `json:"sha256"`
	Status      string `json:"status"`
}

type DataCenterRecord struct {
	Name       string    `json:"name"`
	Company    string    `json:"company"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	CityCoords []float64 `json:"city_coords"`
}

var socketStateCache = make(map[string]LeanConnectionMeta)
var processGuidRegistry = make(map[int32]string)
var pidReferenceCounter = make(map[int32]int)
var sysHostname = "unknown-host"
var fileWriteLock sync.Mutex

var geoCache = make(map[string]GeoCacheData)
var geoCacheLock sync.RWMutex

var maliciousBlacklist = make(map[string]bool)
var blacklistLock sync.RWMutex

var dataCenterCatalog []DataCenterRecord
var dataCenterLock sync.RWMutex

// Parsed networks list for rapid CIDR match lookup
var cloudIPNetworks []net.IPNet
var networkListLock sync.RWMutex

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

func DownloadFileAsset(targetPath string, url string) error {
	if _, err := os.Stat(targetPath); err == nil {
		return nil
	}
	
	// Create parent directories if missing
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func LoadNetworkRanges(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	networkListLock.Lock()
	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet != nil {
			cloudIPNetworks = append(cloudIPNetworks, *ipnet)
		}
	}
	networkListLock.Unlock()
}

func CheckIPAgainstCloudRanges(ipStr string) bool {
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		return false
	}

	networkListLock.RLock()
	defer networkListLock.RUnlock()

	for _, ipnet := range cloudIPNetworks {
		if ipnet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func IsNearDataCenter(lat, lon float64, city, country string) (bool, string) {
	dataCenterLock.RLock()
	defer dataCenterLock.RUnlock()

	cleanCity := strings.ToLower(strings.TrimSpace(city))
	cleanCountry := strings.ToLower(strings.TrimSpace(country))

	for _, dc := range dataCenterCatalog {
		if cleanCity != "" && strings.ToLower(dc.City) == cleanCity && cleanCountry != "" && strings.ToLower(dc.Country) == cleanCountry {
			return true, fmt.Sprintf("%s (%s)", dc.Name, dc.Company)
		}
		if len(dc.CityCoords) == 2 && lat != 0 && lon != 0 {
			dcLat := dc.CityCoords[0]
			dcLon := dc.CityCoords[1]
			distance := math.Sqrt(math.Pow(lat-dcLat, 2) + math.Pow(lon-dcLon, 2))
			if distance < 0.3 { 
				return true, fmt.Sprintf("%s (%s)", dc.Name, dc.Company)
			}
		}
	}
	return false, ""
}

func EvaluateThreatVitals(p *process.Process, path, username, name string) (int, []string) {
	var flags []string
	score := 0
	lowerPath := strings.ToLower(path)
	lowerName := strings.ToLower(name)

	if strings.Contains(lowerName, "powershell") || strings.Contains(lowerName, "cmd.exe") || strings.Contains(lowerName, "wscript") || strings.Contains(lowerName, "mshta") {
		flags = append(flags, "Shell Execution")
		score += 25
	}

	if strings.Contains(lowerPath, "\\appdata\\local\\temp") || strings.Contains(lowerPath, "\\windows\\temp") {
		flags = append(flags, "Executed from Temp")
		score += 20
	}
	if strings.Contains(lowerPath, "\\users\\") && strings.Contains(lowerPath, "\\downloads\\") {
		flags = append(flags, "Executed from Downloads")
		score += 15
	}

	if conns, err := p.Connections(); err == nil && len(conns) > 15 {
		flags = append(flags, "High Network Volume")
		score += 20
	}

	return score, flags
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

		hashLogData := HashAuditData{
			Timestamp:   time.Now().Format(time.RFC3339),
			ProcessGuid: procGuid,
			FileName:    filepath.Base(filePath),
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
				procData.ThreatScore = 100
				procData.ThreatFlags = append(procData.ThreatFlags, "Known Malware Hash")
				WriteEvent(ProcessLog, UnifiedLogEvent{
					Timestamp: time.Now().Format(time.RFC3339),
					Action:    "ALERT",
					Process:   procData,
				})
			}
			memRegistryLock.Unlock()
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
			childName = "Unknown Process"
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

		WriteEvent(ChildLog, ChildProcessEvent{
			Timestamp:         time.Now().Format(time.RFC3339),
			ParentProcessGuid: parentGuid,
			ChildProcessGuid:  childGuid,
			ChildPID:          childPid,
			ChildName:         childName,
		})
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
		url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp,lat,lon", normalizedIP)
		resp, err := http.Get(url)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var result struct {
			Status  string  `json:"status"`
			Country string  `json:"country"`
			City    string  `json:"city"`
			ISP     string  `json:"isp"`
			Lat     float64 `json:"lat"`
			Lon     float64 `json:"lon"`
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
				Latitude:    result.Lat,
				Longitude:   result.Lon,
			}
			geoCacheLock.Lock()
			geoCache[normalizedIP] = geoData
			geoCacheLock.Unlock()
			WriteEvent(GeoLog, geoData)

			// Evaluation Vector: Determine if target IP is outside cloud networks (Home/Residential Network target)
			isDataCenterNetwork := CheckIPAgainstCloudRanges(normalizedIP)
			
			memRegistryLock.Lock()
			if procData, exists := activeProcessMemRegistry[guid]; exists {
				if !isDataCenterNetwork {
					// Anomaly: Target falls outside verified datacenter blocks -> Home Network/Residential IP
					procData.ThreatScore += 15
					if procData.ThreatScore > 100 {
						procData.ThreatScore = 100
					}

					hasFlag := false
					for _, f := range procData.ThreatFlags {
						if f == "Residential/Home Network Target" {
							hasFlag = true
							break
						}
					}
					if !hasFlag {
						procData.ThreatFlags = append(procData.ThreatFlags, "Residential/Home Network Target")
						WriteEvent(ProcessLog, UnifiedLogEvent{
							Timestamp: time.Now().Format(time.RFC3339),
							Action:    "ALERT",
							Process:   procData,
						})
					}
				}
			}
			memRegistryLock.Unlock()
		}
	}()
}

func AnalyzeSocket(conn psnet.ConnectionStat, guid string) LeanConnectionMeta {
	meta := LeanConnectionMeta{
		ProcessGuid: guid, PID: conn.Pid, LocalIP: conn.Laddr.IP, LocalPort: conn.Laddr.Port,
		RemoteIP: conn.Raddr.IP, RemotePort: conn.Raddr.Port, Status: conn.Status,
		IsInternalAgent: conn.Pid == int32(os.Getpid()),
	}
	if conn.Type == 1 { meta.ProtocolType = "TCP" } else { meta.ProtocolType = "UDP" }
	if conn.Family == 2 { meta.IPVersion = "IPv4" } else { meta.IPVersion = "IPv6" }
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

func LazyRegisterProcess(pid int32) string {
	if pid <= 0 { return "00000000-0000-0000-0000-000000000000" }
	if guid, exists := processGuidRegistry[pid]; exists { return guid }

	p, err := process.NewProcess(pid)
	if err != nil {
		processGuidRegistry[pid] = "SYSTEM-PROCESS"
		return "SYSTEM-PROCESS"
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
		score, flags := EvaluateThreatVitals(p, path, user, name)
		procData := ProcessRegistryData{
			ProcessGuid: guid, PID: pid, Name: name, Path: path, CmdLine: cmd,
			Cwd: cwd, Username: user, CreateTime: cTime, ThreatScore: score, ThreatFlags: flags,
		}

		memRegistryLock.Lock()
		activeProcessMemRegistry[guid] = &procData
		memRegistryLock.Unlock()

		WriteEvent(ProcessLog, UnifiedLogEvent{
			Timestamp: time.Now().Format(time.RFC3339), Action: "START", Process: &procData,
		})
		AuditFileHash(guid, path)
	}()
	return guid
}

func StartBackgroundService() {
	isInitialRun := true
	if name, err := os.Hostname(); err == nil { sysHostname = name }
	SessionDataDir = filepath.Join("data", time.Now().Format("20060102_150405"))

	// 1. Download and parse hash list
	_ = DownloadFileAsset(MaliciousDbFile, "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt")
	if dbFile, err := os.Open(MaliciousDbFile); err == nil {
		scanner := bufio.NewScanner(dbFile)
		blacklistLock.Lock()
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				maliciousBlacklist[strings.ToLower(line)] = true
			}
		}
		blacklistLock.Unlock()
		dbFile.Close()
	}

	// 2. Download data centers database mapping
	_ = DownloadFileAsset(DataCenterDbFile, "https://raw.githubusercontent.com/Ringmast4r/Global-Data-Center-Map/refs/heads/main/datacenters.json")
	if dcFile, err := os.Open(DataCenterDbFile); err == nil {
		var records []DataCenterRecord
		if err := json.NewDecoder(dcFile).Decode(&records); err == nil {
			dataCenterLock.Lock()
			dataCenterCatalog = records
			dataCenterLock.Unlock()
		}
		dcFile.Close()
	}

	// 3. Download and compile the All-In-One Cloud/Infrastructure CIDR lists
	_ = DownloadFileAsset(IPv4RangesFile, "https://raw.githubusercontent.com/lord-alfred/ipranges/main/all/ipv4_merged.txt")
	_ = DownloadFileAsset(IPv6RangesFile, "https://raw.githubusercontent.com/lord-alfred/ipranges/main/all/ipv6_merged.txt")
	LoadNetworkRanges(IPv4RangesFile)
	LoadNetworkRanges(IPv6RangesFile)

	for {
		connections, err := psnet.Connections("all")
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		aliveNow := make(map[string]bool)
		myPID := int32(os.Getpid())

		for _, conn := range connections {
			if conn.Pid == myPID { continue }
			guid := LazyRegisterProcess(conn.Pid)
			meta := AnalyzeSocket(conn, guid)
			socketKey := fmt.Sprintf("%s-%s:%d-%s:%d", meta.ProtocolType, meta.LocalIP, meta.LocalPort, meta.RemoteIP, meta.RemotePort)
			aliveNow[socketKey] = true

			if meta.Direction == "OUTBOUND" && !meta.IsLoopback {
				GeolocateRemoteIP(meta.RemoteIP, conn.Pid, guid)
			}
			if conn.Pid > 0 { AuditChildProcesses(conn.Pid, guid) }

			if _, tracked := socketStateCache[socketKey]; !tracked {
				socketStateCache[socketKey] = meta
				pidReferenceCounter[conn.Pid]++
				if !isInitialRun {
					WriteEvent(NetworkLog, UnifiedLogEvent{Timestamp: time.Now().Format(time.RFC3339), Action: "OPEN", Connection: &meta})
				}
			}
		}

		for trackedKey, trackedState := range socketStateCache {
			if !aliveNow[trackedKey] {
				if !isInitialRun {
					WriteEvent(NetworkLog, UnifiedLogEvent{Timestamp: time.Now().Format(time.RFC3339), Action: "CLOSED", Connection: &trackedState})
				}
				pidReferenceCounter[trackedState.PID]--
				
				if pidReferenceCounter[trackedState.PID] <= 0 {
					delete(processGuidRegistry, trackedState.PID)
					delete(pidReferenceCounter, trackedState.PID)
					
					memRegistryLock.Lock()
					if procData, exists := activeProcessMemRegistry[trackedState.ProcessGuid]; exists {
						if !isInitialRun {
							WriteEvent(ProcessLog, UnifiedLogEvent{
								Timestamp: time.Now().Format(time.RFC3339), 
								Action:    "STOP", 
								Process:   procData,
							})
						}
						delete(activeProcessMemRegistry, trackedState.ProcessGuid)
					}
					memRegistryLock.Unlock()
				}
				delete(socketStateCache, trackedKey)
			}
		}
		isInitialRun = false
		time.Sleep(2 * time.Second)
	}
}