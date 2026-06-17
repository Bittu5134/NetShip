package main

import (
	"fmt"
	"os"
)

func main() {
	// NetShip Execution Matrix Routing:
	//   ./netship           → starts the dashboard server on default :8080
	//   ./netship scan      → runs the background scanner directly as a standalone worker
	//   ./netship server    → explicit server mode
	//   ./netship :9000     → server routing on a custom port destination

	arg := ""
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}

	switch arg {
	case "scan":
		fmt.Println("🚀 [ENGINE] Launching decoupled telemetry scanner agent...")
		StartBackgroundService()
	case "", "server":
		StartServer(":8080")
	default:
		if len(arg) > 0 && arg[0] == ':' {
			StartServer(arg)
		} else {
			fmt.Fprintf(os.Stderr, "Usage: %s [scan | server | :PORT]\n", os.Args[0])
			os.Exit(1)
		}
	}
}