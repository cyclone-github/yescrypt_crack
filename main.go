package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

/*
Cyclone's Yescrypt Cracker
POC tool to crack Yescrypt hashes
https://github.com/cyclone-github/yescrypt_crack

written by cyclone in pure Go

GNU General Public License v2.0
https://github.com/cyclone-github/yescrypt_crack/blob/main/LICENSE

Credits:
The yescrypt algo was written by Solar Designer: https://www.openwall.com/yescrypt/
This tool uses their yescrypt-go implementation: https://github.com/openwall/yescrypt-go

version history
v0.1.0; 2024-04-16
	initial POC
...
v0.2.0; 2025-03-06
	refactored code
	github version
v0.3.1; 2026-08-08
	add gost-yescrypt support
*/

// main func
func main() {
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	hashFileFlag := flag.String("h", "", "Yescrypt / gost-yescrypt hash file")
	outputFileFlag := flag.String("o", "", "Output file to write cracked hashes to (omit -o to print to console)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	flag.Parse()

	clearScreen()

	// run sanity checks for special flags
	if *versionFlag {
		versionFunc()
		os.Exit(0)
	}
	if *cycloneFlag {
		line := "Q29kZWQgYnkgY3ljbG9uZSA7KQo="
		str, _ := base64.StdEncoding.DecodeString(line)
		fmt.Println(string(str))
		os.Exit(0)
	}
	if *helpFlag {
		helpFunc()
		os.Exit(0)
	}

	if *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (hash file) flag is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	startTime := time.Now()

	numThreads := setNumThreads(*threadFlag)

	var (
		crackedCount         int32
		linesProcessed       int32
		wg                   sync.WaitGroup
		totalHashesGenerated int32
	)

	stopChan := make(chan struct{})

	handleGracefulShutdown(stopChan)

	hashes, err := ReadYescryptHashes(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
		os.Exit(1)
	}
	totalHashCount := len(hashes)

	printWelcomeScreen(hashFileFlag, wordlistFileFlag, totalHashCount, numThreads)

	wg.Add(1)
	go monitorPrintStats(&crackedCount, &linesProcessed, &totalHashesGenerated, stopChan, startTime, totalHashCount, &wg, *statsIntervalFlag)

	startProc(*wordlistFileFlag, *outputFileFlag, numThreads, hashes, &crackedCount, &linesProcessed, &totalHashesGenerated, stopChan)

	closeStopChannel(stopChan)

	wg.Wait()
}

// end code
