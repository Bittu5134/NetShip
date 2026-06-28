package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "scan":
		fmt.Println("Starting background scanner...")
		StartBackgroundService()

	case "", "server":
		StartServer(":8080")

	default:
		if strings.HasPrefix(cmd, ":") {
			StartServer(cmd)
		} else {
			fmt.Fprintf(os.Stderr, "Usage: %s [scan | server | :PORT]\n", os.Args[0])
			os.Exit(1)
		}
	}
}
