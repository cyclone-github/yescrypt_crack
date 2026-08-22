package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

/*
Cyclone's Yescrypt Cracker
POC tool to crack yescrypt /gost-yescrypt hashes
https://github.com/cyclone-github/yescrypt_crack

GNU General Public License v2.0
https://github.com/cyclone-github/yescrypt_crack/blob/main/LICENSE

Credits:
yescrypt_crack was written by cyclone in Go
The yescrypt algorithm was designed by Solar Designer: https://www.openwall.com/yescrypt/
The CPU yescrypt implementation in yescrypt_cpu.go is adapted from openwall/yescrypt-go: https://github.com/openwall/yescrypt-go
The GPU SMix/PWX implementation in kernels/yescrypt.cl are adapted from hashcat's yescrypt OpenCL implementation: https://github.com/hashcat/hashcat/blob/master/OpenCL/inc_hash_yescrypt.cl
Streebog-256 is provided by github.com/tarantool/go-gostcrypto/streebog
See THIRD_PARTY_NOTICES.md for upstream copyright notices and license terms

version history
v0.4.1-dev; 2026-08-22
	complete rewrite of codebase
	add OpenCL GPU acceleration for yescrypt / gost-yescrypt with CPU fallback
	add ETA status for -w wordlists
*/

type wordlistCountResult struct {
	lines uint64
	err   error
}

// main func
func main() {
	os.Args = normalizeGPUArgs(os.Args)
	wordlistFileFlag := flag.String("w", "", "Input file to process (omit -w to read from stdin)")
	hashFileFlag := flag.String("h", "", "Yescrypt / gost-yescrypt hash file")
	outputFileFlag := flag.String("o", "", "Output file to write cracked hashes to (omit -o to print to console)")
	cycloneFlag := flag.Bool("cyclone", false, "")
	versionFlag := flag.Bool("version", false, "Program version:")
	helpFlag := flag.Bool("help", false, "Prints help:")
	threadFlag := flag.Int("t", runtime.NumCPU(), "CPU threads to use (optional)")
	statsIntervalFlag := flag.Int("s", 60, "Interval in seconds for printing stats. Defaults to 60.")
	gpuFlag := flag.String("gpu", "all", "GPU selection: all, 0, 0,1, or list")
	cpuFlag := flag.Bool("cpu", false, "Force CPU mode")
	gpuBatchFlag := flag.Int("b", 0, "GPU batch size (0 = auto)")
	flag.Parse()

	var (
		gpuSet    bool
		threadSet bool
		batchSet  bool
	)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "gpu":
			gpuSet = true
		case "t":
			threadSet = true
		case "b":
			batchSet = true
		}
	})

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

	if *cpuFlag && gpuSet {
		fmt.Fprintln(os.Stderr, "-cpu and -gpu cannot be used together")
		os.Exit(1)
	}
	if gpuSet && threadSet {
		fmt.Fprintln(os.Stderr, "-gpu and -t cannot be used together (-t is for CPU mode)")
		os.Exit(1)
	}
	if (*cpuFlag || threadSet) && batchSet {
		fmt.Fprintln(os.Stderr, "-b is only valid in GPU mode")
		os.Exit(1)
	}
	if *gpuBatchFlag < 0 {
		fmt.Fprintln(os.Stderr, "-b must be >= 0")
		os.Exit(1)
	}
	if *statsIntervalFlag < 0 {
		fmt.Fprintln(os.Stderr, "-s must be >= 0")
		os.Exit(1)
	}

	if gpuSet && strings.EqualFold(strings.TrimSpace(*gpuFlag), "list") {
		printGPUList()
		os.Exit(0)
	}

	if *hashFileFlag == "" {
		fmt.Fprintln(os.Stderr, "-h (hash file) flag is required")
		fmt.Fprintln(os.Stderr, "Try running with -help for usage instructions")
		os.Exit(1)
	}

	cpuMode := *cpuFlag || threadSet
	numThreads := setNumThreads(*threadFlag)

	var (
		crackedCount         int32
		linesProcessed       uint64
		wg                   sync.WaitGroup
		totalHashesGenerated uint64
	)

	stopChan := make(chan struct{})
	handleGracefulShutdown(stopChan)

	hashes, err := ReadYescryptHashes(*hashFileFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading hash file:", err)
		os.Exit(1)
	}
	totalHashCount := len(hashes)
	if totalHashCount == 0 {
		fmt.Fprintln(os.Stderr, "No supported yescrypt / gost-yescrypt hashes found")
		os.Exit(1)
	}

	groups := makeHashGroups(hashes)
	var selectedGPUs []GPUDeviceInfo
	var fallbackReason string
	displayBatch := 0

	if !cpuMode {
		devices, derr := ListOpenCLGPUs()
		if derr != nil {
			cpuMode = true
			fallbackReason = fmt.Sprintf("OpenCL unavailable (%v); falling back to CPU", derr)
		} else {
			selectedGPUs, err = parseGPUSelection(*gpuFlag, devices)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if len(selectedGPUs) == 0 {
				cpuMode = true
				fallbackReason = "No OpenCL GPU devices found; falling back to CPU"
			} else if len(groups) == 0 {
				cpuMode = true
				fallbackReason = "No GPU-compatible yescrypt groups found; falling back to CPU"
			} else {
				// RTX 4090s auto-tuned measured value was 1280
				for _, info := range selectedGPUs {
					cap := minGPUCapacity(info, groups, *gpuBatchFlag)
					if cap > 0 && (displayBatch == 0 || cap < displayBatch) {
						displayBatch = cap
					}
				}
			}
		}
	}

	welcome := WelcomeOptions{Backend: "CPU"}
	if !cpuMode {
		welcome.Backend = "GPU"
		welcome.GPUSelection = *gpuFlag
		welcome.GPUBatch = displayBatch
	}
	printWelcomeScreen(hashFileFlag, wordlistFileFlag, totalHashCount, numThreads, welcome)
	if fallbackReason != "" {
		log.Println(fallbackReason)
	}

	var countCh chan wordlistCountResult
	if *wordlistFileFlag != "" {
		log.Println("Counting wordlist lines...")
		countCh = make(chan wordlistCountResult, 1)
		go func() {
			lines, err := countWordlistLinesStop(*wordlistFileFlag, stopChan)
			countCh <- wordlistCountResult{lines: lines, err: err}
		}()
	}

	var gpuPrepCh chan *gpuRuntime
	if !cpuMode {
		log.Println("Tuning GPU...")
		gpuPrepCh = make(chan *gpuRuntime, 1)
		go func() {
			gpuPrepCh <- prepareGPUProcessor(selectedGPUs, *gpuBatchFlag, groups, hashes, stopChan)
		}()
	}

	var totalWordlistLines uint64
	if countCh != nil {
		result := <-countCh
		if result.err == nil {
			totalWordlistLines = result.lines
		} else if !errors.Is(result.err, errWordlistCountCancelled) {
			log.Printf("Unable to count wordlist lines for ETA: %v", result.err)
		}
	}

	var preparedGPU *gpuRuntime
	if gpuPrepCh != nil {
		preparedGPU = <-gpuPrepCh
		if preparedGPU == nil {
			cpuMode = true
			log.Println("GPU tuning failed; falling back to CPU")
		}
	}

	select {
	case <-stopChan:
		if preparedGPU != nil {
			preparedGPU.Close()
		}
		return
	default:
	}

	startTime := time.Now()
	log.Println("Working...")

	wg.Add(1)
	go monitorPrintStats(&crackedCount, &linesProcessed, &totalHashesGenerated, stopChan, startTime, totalHashCount, totalWordlistLines, &wg, *statsIntervalFlag)

	procErr := startProcWithOptions(
		*wordlistFileFlag,
		*outputFileFlag,
		numThreads,
		hashes,
		&crackedCount,
		&linesProcessed,
		&totalHashesGenerated,
		stopChan,
		RuntimeOptions{UseGPU: !cpuMode, GPUList: *gpuFlag, GPUBatch: *gpuBatchFlag, PreparedGPU: preparedGPU},
	)

	closeStopChannel(stopChan)
	wg.Wait()
	if procErr != nil {
		log.Printf("%v", procErr)
		log.Println("GPU processing aborted. Re-run with -cpu to use the CPU backend.")
		os.Exit(1)
	}
}

// end code
