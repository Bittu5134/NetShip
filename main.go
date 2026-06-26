package main

import (
	"fmt"
	"os"
)

func main() {
	argumentString := ""
	argumentCount := len(os.Args)
	
	if argumentCount > 1 {
		argumentString = os.Args[1]
	}

	switch argumentString {
	case "scan":
		fmt.Println("Starting scanner background service...")
		StartBackgroundService()
		
	case "", "server":
		defaultPortAddress := ":8080"
		StartServer(defaultPortAddress)
		
	default:
		argumentLength := len(argumentString)
		isCustomPort := false
		
		if argumentLength > 0 {
			firstCharacter := argumentString[0]
			if firstCharacter == ':' {
				isCustomPort = true
			}
		}

		if isCustomPort {
			StartServer(argumentString)
		} else {
			fmt.Fprintf(os.Stderr, "Usage command format: %s [scan | server | :PORT]\n", os.Args[0])
			os.Exit(1)
		}
	}
}