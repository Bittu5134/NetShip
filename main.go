package main

import (
	"fmt"
	"os"
)

func main() {
	arg := ""
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}

	switch arg {
	case "scan":
		fmt.Println("Starting NetShip background scanner...")
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