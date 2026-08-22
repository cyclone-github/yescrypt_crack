package main

import (
	"fmt"
	"os"
)

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Yescrypt Cracker v0.4.1-dev; 2026-08-22\nhttps://github.com/cyclone-github/yescrypt_crack ")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {yescrypt_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads} (selects CPU mode)
-s {print status every nth sec)
-gpu [all|0,1|list] (default: all GPUs; omit value to use all GPUs)
-cpu (force CPU mode)
-b {gpu batch size} (optional; 0 = auto)

-version (version info)
-help (usage instructions)

./yescrypt_crack.bin -h {yescrypt_hash_file} -w {wordlist} -o {output} -gpu -s {print status every nth sec}

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -o cracked.txt -gpu 0,1 -s 10

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -gpu 0,1 -b 1280 -s 10

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -cpu -t 16 -s 10

cat wordlist | ./yescrypt_crack.bin -h hashes.txt

./yescrypt_crack.bin -gpu list`
	fmt.Fprintln(os.Stderr, str)
}

type WelcomeOptions struct {
	Backend      string
	GPUSelection string
	GPUBatch     int
}

// print welcome screen
func printWelcomeScreen(hashFileFlag, wordlistFileFlag *string, totalHashCount, numThreads int, opts WelcomeOptions) {
	fmt.Fprintln(os.Stderr, " -------------------------------------------------- ")
	fmt.Fprintln(os.Stderr, "|            Cyclone's Yescrypt Cracker            |")
	fmt.Fprintln(os.Stderr, "| https://github.com/cyclone-github/yescrypt_crack |")
	fmt.Fprintln(os.Stderr, " -------------------------------------------------- ")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Hash file:\t%s\n", *hashFileFlag)
	fmt.Fprintf(os.Stderr, "Total Hashes:\t%d\n", totalHashCount)
	fmt.Fprintf(os.Stderr, "CPU Threads:\t%d\n", numThreads)

	if *wordlistFileFlag == "" {
		fmt.Fprintf(os.Stderr, "Wordlist:\tReading from stdin\n")
	} else {
		fmt.Fprintf(os.Stderr, "Wordlist:\t%s\n", *wordlistFileFlag)
	}

	fmt.Fprintf(os.Stderr, "Backend:\t%s\n", opts.Backend)
	if opts.Backend == "GPU" {
		fmt.Fprintf(os.Stderr, "GPU selection:\t%s\n", opts.GPUSelection)
		if opts.GPUBatch > 0 {
			fmt.Fprintf(os.Stderr, "GPU batch:\t%d\n", opts.GPUBatch)
		} else {
			fmt.Fprintf(os.Stderr, "GPU batch:\tauto\n")
		}
	}
}

func printGPUList() {
	devices, err := ListOpenCLGPUs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "OpenCL:", err)
		return
	}
	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "No OpenCL GPU devices found")
		return
	}

	for _, device := range devices {
		fmt.Printf("GPU %d: %s  VRAM %.1f GiB\n", device.Index, device.Name, float64(device.GlobalMem)/(1<<30))
	}
}
