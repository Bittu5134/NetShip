<div align="center">

# NetShip

### A host network monitoring and security auditing tool.

</div>

NetShip is a local host monitoring utility that tracks socket connections, profiles process lifecycles, and logs threat telemetry. It provides an embedded web dashboard for real-time traffic analysis, process lineage tree visualization, and system state comparison.

---

## Features

* **Network Tracking:** Logs active TCP/UDP sockets (IPv4/IPv6) with local and remote endpoints, directionality, and connection states.
* **Process Profiling:** Tracks process registry events, parent-child execution lineages, execution paths, and command-line arguments.
* **Threat Auditing:** Computes SHA256 hashes of running binaries to check against known malware databases and calculates threat scores based on process paths, parentage, and network volumes.
* **IP Geolocation:** Resolves external IPs using public databases to plot coordinates and determine proximity to enterprise cloud datacenters.

---

## Dashboard Views

The web dashboard is served directly from the application and contains:

* **Overview:** System statistics (active connections, scanned hashes) and the latest threat alerts ledger.
* **Analytics:** Process activity timelines, protocol ratios (TCP vs. UDP), port distributions, and process churn charts.
* **Network Map:** Geospatial mapping of outbound IP targets relative to global datacenter nodes.
* **Process Tree:** Real-time tree view of process ancestry and parent-child spawning relationships.
* **Sessions & Diff Matrix:** Historic session explorer and comparison tool to analyze process drift between two runs.

---

## Setup & Running

### Prerequisites

* Go 1.26 or higher
* Internet connection (on initial scan to fetch updated cloud CIDRs and threat databases)

### Instructions

1. **Download dependencies:**
   ```bash
   go mod download
   ```

2. **Build the binary:**
   ```bash
   go build -o NetShip.exe .
   ```

3. **Start the server:**
   ```bash
   ./NetShip.exe server
   ```
   Open **[http://localhost:8080](http://localhost:8080)** in your browser to view the interface.

---

## Command Line Usage

Configure execution mode using arguments:

| Argument | Example | Description |
| :--- | :--- | :--- |
| `server` | `NetShip.exe server` | Runs the HTTP web portal (default port: `:8080`). |
| `scan` | `NetShip.exe scan` | Starts the background monitoring scanner process directly. |
| `:PORT` | `NetShip.exe :9090` | Runs the HTTP web portal on a custom port. |

---

## API Reference

The dashboard communicates with the backend via the following HTTP endpoints:

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/status` | `GET` | Returns scanning state and active session ID. |
| `/api/scan/start` | `POST` | Spawns the background scanner process. |
| `/api/scan/stop` | `POST` | Terminates the running scanner process. |
| `/api/live/<channel>` | `GET` | Pulls live records (`network`, `process`, `children`, `geo`, `hashes`). |
| `/api/sessions` | `GET` | Lists all historical scan session records. |
| `/api/session/<id>/<channel>` | `GET` | Fetches historical log lines for a specific session ID and data channel. |

---

## Data Layout

### Local Logs
All logs are written in JSON Lines (JSONL) format under `data/<session_timestamp>/`:
* `network.jsonl`: Logs socket lifecycle transitions.
* `processes.jsonl`: Logs process registry states and alerts.
* `children.jsonl`: Logs process parentage relationships.
* `geolocation.jsonl`: Caches resolved IP geolocations.
* `threat_hashes.jsonl`: Stores computed hash audit results.

### Resource Databases
Datasets downloaded and cached under the `resources/` folder on startup:
* `malicious_hashes.txt`: Database of known bad binary signatures.
* `datacenters.json`: Public records of major cloud service provider zones.
* `ipv4_merged.txt` / `ipv6_merged.txt`: Consolidated cloud CIDR lists.

---

## License

This project is licensed under the MIT License.
