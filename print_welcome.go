package main

import (
	"fmt"
	"log"
	"os"
)

// version func
func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone's Yescrypt Cracker v0.3.1; 2026-08-08\nhttps://github.com/cyclone-github/yescrypt_crack\n ")
}

// help func
func helpFunc() {
	versionFunc()
	str := `Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {yescrypt_hash_file}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec)

-version (version info)
-help (usage instructions)

./yescrypt_crack.bin -h {yescrypt_hash_file} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | ./yescrypt_crack.bin -h hashes.txt

./yescrypt_crack.bin -h hashes.txt -w wordlist.txt -o output.txt`
	fmt.Fprintln(os.Stderr, str)
}

// print welcome screen
func printWelcomeScreen(hashFileFlag, wordlistFileFlag *string, totalHashCount, numThreads int) {
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

	log.Println("Working...")
}
