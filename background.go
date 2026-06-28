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

type Socket struct {
	Guid       string `json:"guid"`
	Pid        int32  `json:"pid"`
	Protocol   string `json:"protocol"`
	IpVersion  string `json:"ip_version"`
	LocalIp    string `json:"local_ip"`
	LocalPort  uint32 `json:"local_port"`
	RemoteIp   string `json:"remote_ip,omitempty"`
	RemotePort uint32 `json:"remote_port,omitempty"`
	Direction  string `json:"direction"`
	State      string `json:"state"`
	IsLoopback bool   `json:"is_loopback"`
	Hostname   string `json:"hostname,omitempty"`
}

type Process struct {
	Guid        string   `json:"guid"`
	Pid         int32    `json:"pid"`
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	Cmdline     string   `json:"cmdline,omitempty"`
	Cwd         string   `json:"cwd,omitempty"`
	User        string   `json:"user,omitempty"`
	CreatedTime int64    `json:"created_time,omitempty"`
	RiskScore   int      `json:"risk_score"`
	RiskReasons []string `json:"risk_reasons,omitempty"`
}

type Event struct {
	Timestamp string   `json:"timestamp"`
	Action    string   `json:"action"`
	Socket    *Socket  `json:"socket,omitempty"`
	Process   *Process `json:"process,omitempty"`
}

type ChildSpawn struct {
	Timestamp  string `json:"timestamp"`
	ParentGuid string `json:"parent_guid"`
	ChildGuid  string `json:"child_guid"`
	ChildPid   int32  `json:"child_pid"`
	ChildName  string `json:"child_name"`
}

type Geolocation struct {
	Timestamp   string  `json:"timestamp"`
	Ip          string  `json:"ip"`
	Pid         int32   `json:"pid"`
	ProcessGuid string  `json:"process_guid"`
	Country     string  `json:"country"`
	City        string  `json:"city"`
	Isp         string  `json:"isp"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Hostname    string  `json:"hostname,omitempty"`
}

type FileSignature struct {
	Timestamp   string `json:"timestamp"`
	ProcessGuid string `json:"process_guid"`
	FileName    string `json:"file_name"`
	Sha256      string `json:"sha256"`
	Status      string `json:"status"`
}

type Datacenter struct {
	Name       string    `json:"name"`
	Company    string    `json:"company"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	CityCoords []float64 `json:"city_coords"`
}

var (
	SessionDataDir   string
	NetworkLog       = "network.jsonl"
	ProcessLog       = "processes.jsonl"
	ChildLog         = "children.jsonl"
	GeoLog           = "geolocation.jsonl"
	HashLog          = "threat_hashes.jsonl"
	ResourcesDir     = "resources"
	MaliciousDbFile  = filepath.Join(ResourcesDir, "malicious_hashes.txt")
	DataCenterDbFile = filepath.Join(ResourcesDir, "datacenters.json")
	IPv4RangesFile   = filepath.Join(ResourcesDir, "ipv4_merged.txt")
	IPv6RangesFile   = filepath.Join(ResourcesDir, "ipv6_merged.txt")
	sysHostname      = "unknown-host"

	socketRegistry       = make(map[string]Socket)
	processGuidRegistry  = make(map[int32]string)
	socketReferenceCount = make(map[int32]int)
	geolocationCache     = make(map[string]Geolocation)
	maliciousHashes      = make(map[string]bool)
	datacentersCatalog   = make([]Datacenter, 0)
	cloudCidrNetworks    = make([]net.IPNet, 0)
	loggedFileSignatures = make(map[string]bool)
	loggedRelationships  = make(map[string]bool)
	activeProcessCache   = make(map[string]*Process)
	hostnameCache        = make(map[string]string)

	fileWriteLock      sync.Mutex
	geoCacheLock       sync.RWMutex
	blacklistLock      sync.RWMutex
	datacenterLock     sync.RWMutex
	networkCidrLock    sync.RWMutex
	signatureCacheLock sync.Mutex
	relationshipLock   sync.Mutex
	processCacheLock   sync.Mutex
	hostnameCacheLock  sync.RWMutex
)

func ResolveIPHostname(ipStr string) string {
	names, err := net.LookupAddr(ipStr)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func GetHostname(ip string) string {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return ""
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return ""
	}

	hostnameCacheLock.RLock()
	cached, exists := hostnameCache[ip]
	hostnameCacheLock.RUnlock()

	if exists {
		return cached
	}

	go func() {
		if resolved := ResolveIPHostname(ip); resolved != "" {
			hostnameCacheLock.Lock()
			hostnameCache[ip] = resolved
			hostnameCacheLock.Unlock()
		}
	}()

	return ""
}

func QueryThreatFoxIOC(term string) (bool, string) {
	client := &http.Client{Timeout: 5 * time.Second}
	payload := fmt.Sprintf(`{"query": "search_ioc", "search_term": "%s"}`, term)
	resp, err := client.Post("https://threatfox-api.abuse.ch/api/v1/", "application/json", strings.NewReader(payload))
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	var res struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			MalwarePrint string `json:"malware_printable"`
			Confidence   int    `json:"confidence_level"`
			ThreatType   string `json:"threat_type"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, ""
	}

	if res.QueryStatus == "ok" && len(res.Data) > 0 {
		info := fmt.Sprintf("ThreatFox: %s (%s, Confidence: %d%%)", res.Data[0].MalwarePrint, res.Data[0].ThreatType, res.Data[0].Confidence)
		return true, info
	}

	return false, ""
}

func GenerateProcessGuid(pid int32, createTime int64) string {
	raw := fmt.Sprintf("%s-%d-%d", sysHostname, pid, createTime)
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", sum)[:24]
}

func WriteEvent(filename string, event interface{}) {
	fileWriteLock.Lock()
	defer fileWriteLock.Unlock()

	if err := os.MkdirAll(SessionDataDir, 0755); err != nil {
		return
	}

	file, err := os.OpenFile(filepath.Join(SessionDataDir, filename), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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
	networkCidrLock.Lock()
	defer networkCidrLock.Unlock()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if _, ipNet, err := net.ParseCIDR(line); err == nil && ipNet != nil {
			cloudCidrNetworks = append(cloudCidrNetworks, *ipNet)
		}
	}
}

func CheckIPAgainstCloudRanges(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	networkCidrLock.RLock()
	defer networkCidrLock.RUnlock()

	for _, network := range cloudCidrNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func IsNearDataCenter(lat, lon float64, city, country string) (bool, string) {
	datacenterLock.RLock()
	defer datacenterLock.RUnlock()

	searchCity := strings.ToLower(strings.TrimSpace(city))
	searchCountry := strings.ToLower(strings.TrimSpace(country))

	for _, dc := range datacentersCatalog {
		if searchCity != "" && strings.ToLower(dc.City) == searchCity {
			if searchCountry != "" && strings.ToLower(dc.Country) == searchCountry {
				return true, fmt.Sprintf("%s (%s)", dc.Name, dc.Company)
			}
		}

		if len(dc.CityCoords) == 2 && lat != 0 && lon != 0 {
			dcLat := dc.CityCoords[0]
			dcLon := dc.CityCoords[1]

			dist := math.Sqrt(math.Pow(lat-dcLat, 2) + math.Pow(lon-dcLon, 2))
			if dist < 0.3 {
				return true, fmt.Sprintf("%s (%s)", dc.Name, dc.Company)
			}
		}
	}

	return false, ""
}

func EvaluateThreatVitals(p *process.Process, path, username, name string) (int, []string) {
	var reasons []string
	score := 0
	lowerPath := strings.ToLower(path)
	lowerName := strings.ToLower(name)

	if strings.Contains(lowerName, "powershell") || strings.Contains(lowerName, "cmd.exe") || strings.Contains(lowerName, "wscript") || strings.Contains(lowerName, "mshta") {
		reasons = append(reasons, "Shell Execution")
		score += 25
	}

	if strings.Contains(lowerPath, "\\appdata\\local\\temp") || strings.Contains(lowerPath, "\\windows\\temp") {
		reasons = append(reasons, "Executed from Temp")
		score += 20
	}
	if strings.Contains(lowerPath, "\\users\\") && strings.Contains(lowerPath, "\\downloads\\") {
		reasons = append(reasons, "Executed from Downloads")
		score += 15
	}

	if connections, err := p.Connections(); err == nil {
		if len(connections) > 15 {
			reasons = append(reasons, "High Network Volume")
			score += 20
		}
	}

	return score, reasons
}

// Audits the process binary executable hash
func AuditFileHash(procGuid string, filePath string) {
	if filePath == "" {
		return
	}
	if filePath == "ACCESS_DENIED" {
		return
	}

	signatureCacheLock.Lock()
	isLogged := loggedFileSignatures[procGuid]
	if isLogged {
		signatureCacheLock.Unlock()
		return
	}
	loggedFileSignatures[procGuid] = true
	signatureCacheLock.Unlock()

	go func() {
		file, err := os.Open(filePath)
		if err != nil {
			return
		}
		defer file.Close()

		hasher := sha256.New()
		_, err = io.Copy(hasher, file)
		if err != nil {
			return
		}
		shaSignature := fmt.Sprintf("%x", hasher.Sum(nil))

		signatureEvent := FileSignature{
			Timestamp:   time.Now().Format(time.RFC3339),
			ProcessGuid: procGuid,
			FileName:    filepath.Base(filePath),
			Sha256:      shaSignature,
			Status:      "CLEAN",
		}

		// Check local malicious blocklist
		blacklistLock.RLock()
		isMalicious := maliciousHashes[shaSignature]
		blacklistLock.RUnlock()

		if isMalicious {
			signatureEvent.Status = "MALICIOUS"
			WriteEvent(HashLog, signatureEvent)

			processCacheLock.Lock()
			procData, exists := activeProcessCache[procGuid]
			if exists {
				procData.RiskScore = 100
				procData.RiskReasons = append(procData.RiskReasons, "Known Malware Hash")
				WriteEvent(ProcessLog, Event{
					Timestamp: time.Now().Format(time.RFC3339),
					Action:    "ALERT",
					Process:   procData,
				})
			}
			processCacheLock.Unlock()
			return
		}

		// Check ThreatFox API in real-time
		ok, threatDetails := QueryThreatFoxIOC(shaSignature)
		if ok {
			signatureEvent.Status = "MALICIOUS"
			signatureEvent.FileName = fmt.Sprintf("%s [%s]", signatureEvent.FileName, threatDetails)
			WriteEvent(HashLog, signatureEvent)

			processCacheLock.Lock()
			procData, exists := activeProcessCache[procGuid]
			if exists {
				procData.RiskScore = 100
				procData.RiskReasons = append(procData.RiskReasons, threatDetails)
				WriteEvent(ProcessLog, Event{
					Timestamp: time.Now().Format(time.RFC3339),
					Action:    "ALERT",
					Process:   procData,
				})
			}
			processCacheLock.Unlock()
			return
		}

		WriteEvent(HashLog, signatureEvent)
	}()
}

// Queries process child processes and records them
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
		childName, err := child.Name()
		if err != nil || childName == "" {
			childName = "Unknown Process"
		}

		createdTime, _ := child.CreateTime()
		childGuid := GenerateProcessGuid(childPid, createdTime)
		relationshipKey := fmt.Sprintf("%s->%s", parentGuid, childGuid)

		relationshipLock.Lock()
		alreadyLogged := loggedRelationships[relationshipKey]
		if alreadyLogged {
			relationshipLock.Unlock()
			continue
		}
		loggedRelationships[relationshipKey] = true
		relationshipLock.Unlock()

		WriteEvent(ChildLog, ChildSpawn{
			Timestamp:  time.Now().Format(time.RFC3339),
			ParentGuid: parentGuid,
			ChildGuid:  childGuid,
			ChildPid:   childPid,
			ChildName:  childName,
		})
	}
}

// Geotargets remote connections and processes IP reputation queries
func GeolocateRemoteIP(ip string, pid int32, guid string) {
	if ip == "" {
		return
	}
	if ip == "127.0.0.1" || ip == "::1" {
		return
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return
	}

	normalizedIP := strings.ToLower(ip)
	geoCacheLock.RLock()
	_, exists := geolocationCache[normalizedIP]
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

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return
		}

		if result.Status == "success" {
			geoData := Geolocation{
				Timestamp:   time.Now().Format(time.RFC3339),
				Ip:          normalizedIP,
				Pid:         pid,
				ProcessGuid: guid,
				Country:     result.Country,
				City:        result.City,
				Isp:         result.ISP,
				Latitude:    result.Lat,
				Longitude:   result.Lon,
				Hostname:    ResolveIPHostname(normalizedIP),
			}

			geoCacheLock.Lock()
			geolocationCache[normalizedIP] = geoData
			geoCacheLock.Unlock()

			WriteEvent(GeoLog, geoData)

			if ok, threatDetails := QueryThreatFoxIOC(normalizedIP); ok {
				processCacheLock.Lock()
				if procData, exists := activeProcessCache[guid]; exists {
					procData.RiskScore = 100
					procData.RiskReasons = append(procData.RiskReasons, threatDetails)
					WriteEvent(ProcessLog, Event{
						Timestamp: time.Now().Format(time.RFC3339),
						Action:    "ALERT",
						Process:   procData,
					})
				}
				processCacheLock.Unlock()
			}

			if !CheckIPAgainstCloudRanges(normalizedIP) {
				processCacheLock.Lock()
				if procData, exists := activeProcessCache[guid]; exists {
					procData.RiskScore += 15
					if procData.RiskScore > 100 {
						procData.RiskScore = 100
					}

					hasFlag := false
					for _, reason := range procData.RiskReasons {
						if reason == "Residential/Home Network Target" {
							hasFlag = true
							break
						}
					}

					if !hasFlag {
						procData.RiskReasons = append(procData.RiskReasons, "Residential/Home Network Target")
						WriteEvent(ProcessLog, Event{
							Timestamp: time.Now().Format(time.RFC3339),
							Action:    "ALERT",
							Process:   procData,
						})
					}
				}
				processCacheLock.Unlock()
			}
		}
	}()
}

func ParseSocketProperties(conn psnet.ConnectionStat, guid string) Socket {
	socket := Socket{
		Guid:       guid,
		Pid:        conn.Pid,
		LocalIp:    conn.Laddr.IP,
		LocalPort:  conn.Laddr.Port,
		RemoteIp:   conn.Raddr.IP,
		RemotePort: conn.Raddr.Port,
		State:      conn.Status,
		IsLoopback: false,
		Hostname:   GetHostname(conn.Raddr.IP),
	}

	if conn.Type == 1 {
		socket.Protocol = "TCP"
	} else {
		socket.Protocol = "UDP"
	}

	if conn.Family == 2 {
		socket.IpVersion = "IPv4"
	} else {
		socket.IpVersion = "IPv6"
	}

	if conn.Status == "LISTEN" || (conn.Raddr.IP == "" && conn.Raddr.Port == 0) {
		socket.Direction = "INBOUND"
	} else {
		socket.Direction = "OUTBOUND"
	}

	if conn.Laddr.IP == "127.0.0.1" || conn.Laddr.IP == "::1" || conn.Raddr.IP == "127.0.0.1" || conn.Raddr.IP == "::1" {
		socket.IsLoopback = true
	}

	return socket
}

func RegisterRunningProcess(pid int32) string {
	if pid <= 0 {
		return "SYSTEM-PROCESS"
	}

	if guid, exists := processGuidRegistry[pid]; exists {
		return guid
	}

	proc, err := process.NewProcess(pid)
	if err != nil {
		processGuidRegistry[pid] = "SYSTEM-PROCESS"
		return "SYSTEM-PROCESS"
	}

	name, err := proc.Name()
	if err != nil || name == "" {
		name = "Unknown Process"
	}

	path, _ := proc.Exe()
	cmdline, _ := proc.Cmdline()
	cwd, _ := proc.Cwd()
	username, _ := proc.Username()
	createdTime, _ := proc.CreateTime()

	guid := GenerateProcessGuid(pid, createdTime)
	processGuidRegistry[pid] = guid

	go func() {
		score, reasons := EvaluateThreatVitals(proc, path, username, name)
		procRecord := Process{
			Guid:        guid,
			Pid:         pid,
			Name:        name,
			Path:        path,
			Cmdline:     cmdline,
			Cwd:         cwd,
			User:        username,
			CreatedTime: createdTime,
			RiskScore:   score,
			RiskReasons: reasons,
		}

		processCacheLock.Lock()
		activeProcessCache[guid] = &procRecord
		processCacheLock.Unlock()

		WriteEvent(ProcessLog, Event{
			Timestamp: time.Now().Format(time.RFC3339),
			Action:    "START",
			Process:   &procRecord,
		})

		AuditFileHash(guid, path)
	}()

	return guid
}

func StartBackgroundService() {
	isInitialRun := true
	if hostname, err := os.Hostname(); err == nil {
		sysHostname = hostname
	}

	SessionDataDir = filepath.Join("data", time.Now().Format("20060102_150405"))

	_ = DownloadFileAsset(MaliciousDbFile, "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/refs/heads/main/full-hash-sha256-aa.txt")
	if dbFile, err := os.Open(MaliciousDbFile); err == nil {
		scanner := bufio.NewScanner(dbFile)
		blacklistLock.Lock()
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				maliciousHashes[strings.ToLower(line)] = true
			}
		}
		blacklistLock.Unlock()
		dbFile.Close()
	}

	_ = DownloadFileAsset(DataCenterDbFile, "https://raw.githubusercontent.com/Ringmast4r/Global-Data-Center-Map/refs/heads/main/datacenters.json")
	if dcFile, err := os.Open(DataCenterDbFile); err == nil {
		var records []Datacenter
		if err := json.NewDecoder(dcFile).Decode(&records); err == nil {
			datacenterLock.Lock()
			datacentersCatalog = records
			datacenterLock.Unlock()
		}
		dcFile.Close()
	}

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

		activeSocketsNow := make(map[string]bool)
		myPID := int32(os.Getpid())

		for _, conn := range connections {
			if conn.Pid == myPID {
				continue
			}

			processGuid := RegisterRunningProcess(conn.Pid)
			socketProperties := ParseSocketProperties(conn, processGuid)

			socketKey := fmt.Sprintf("%s-%s:%d-%s:%d", socketProperties.Protocol, socketProperties.LocalIp, socketProperties.LocalPort, socketProperties.RemoteIp, socketProperties.RemotePort)
			activeSocketsNow[socketKey] = true

			if socketProperties.Direction == "OUTBOUND" && !socketProperties.IsLoopback {
				GeolocateRemoteIP(socketProperties.RemoteIp, conn.Pid, processGuid)
			}
			if conn.Pid > 0 {
				AuditChildProcesses(conn.Pid, processGuid)
			}

			if _, exists := socketRegistry[socketKey]; !exists {
				socketRegistry[socketKey] = socketProperties
				socketReferenceCount[conn.Pid]++

				if !isInitialRun {
					WriteEvent(NetworkLog, Event{
						Timestamp: time.Now().Format(time.RFC3339),
						Action:    "OPEN",
						Socket:    &socketProperties,
					})
				}
			}
		}

		for key, trackedSocket := range socketRegistry {
			if !activeSocketsNow[key] {
				if !isInitialRun {
					WriteEvent(NetworkLog, Event{
						Timestamp: time.Now().Format(time.RFC3339),
						Action:    "CLOSED",
						Socket:    &trackedSocket,
					})
				}

				socketReferenceCount[trackedSocket.Pid]--
				if socketReferenceCount[trackedSocket.Pid] <= 0 {
					delete(processGuidRegistry, trackedSocket.Pid)
					delete(socketReferenceCount, trackedSocket.Pid)

					processCacheLock.Lock()
					if procRecord, exists := activeProcessCache[trackedSocket.Guid]; exists {
						if !isInitialRun {
							WriteEvent(ProcessLog, Event{
								Timestamp: time.Now().Format(time.RFC3339),
								Action:    "STOP",
								Process:   procRecord,
							})
						}
						delete(activeProcessCache, trackedSocket.Guid)
					}
					processCacheLock.Unlock()
				}

				delete(socketRegistry, key)
			}
		}

		isInitialRun = false
		time.Sleep(2 * time.Second)
	}
}
