package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
)

// process logic
func startProc(wordlistFileFlag string, outputPath string, numGoroutines int, hashes []YescryptHash, crackedCount *int32, linesProcessed *int32, totalHashesGenerated *int32, stopChan chan struct{}) {
	var file *os.File
	var err error

	if wordlistFileFlag == "" {
		file = os.Stdin
	} else {
		file, err = os.Open(wordlistFileFlag)
		if err != nil {
			log.Fatalf("Error opening file: %v\n", err)
		}
		defer file.Close()
	}

	var outputFile *os.File
	if outputPath != "" {
		outputFile, err = os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Error opening output file: %v", err)
		}
		defer outputFile.Close()
	}

	var writer *bufio.Writer
	if outputPath != "" {
		writer = bufio.NewWriter(outputFile)
	} else {
		writer = bufio.NewWriter(os.Stdout)
	}
	defer writer.Flush()

	var (
		writerMu sync.Mutex
		wg       sync.WaitGroup
	)

	// start worker goroutines
	linesCh := make(chan []byte, 1000)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range linesCh {
				processPassword(password, hashes, &writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
			}
		}()
	}

	// read lines from file and send them to workers
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		decodedPassword, _, _ := checkForHexBytes(line)
		password := make([]byte, len(decodedPassword))
		copy(password, decodedPassword)
		linesCh <- password
	}
	close(linesCh)

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file: %v\n", err)
	}

	wg.Wait()

	log.Println("Finished")
}

func processPassword(password []byte, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount, linesProcessed, totalHashesGenerated *int32, stopChan chan struct{}) {
	atomic.AddInt32(linesProcessed, 1)
	// check for hex, ignore hexErrCount
	decodedPassword, _, _ := checkForHexBytes(password)

	for i := range hashes {
		if atomic.LoadInt32(&hashes[i].Cracked) == 0 {
			atomic.AddInt32(totalHashesGenerated, 1)
			if crackHash(decodedPassword, []byte(hashes[i].Hash)) {
				if atomic.CompareAndSwapInt32(&hashes[i].Cracked, 0, 1) {
					output := fmt.Sprintf("%s:%s\n", hashes[i].Hash, string(decodedPassword))
					if writer != nil {
						writerMu.Lock()
						atomic.AddInt32(crackedCount, 1)
						writer.WriteString(output)
						writer.Flush()
						writerMu.Unlock()
					}

					// exit if all hashes are cracked
					if isAllHashesCracked(hashes) {
						closeStopChannel(stopChan)
						return
					}
				}
			}
		}
	}
}
