package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	newlineSeparator          = []byte{'\n'}
	errWordlistCountCancelled = errors.New("wordlist line count cancelled")
)

func closeStopChannel(stopChan chan struct{}) {
	select {
	case <-stopChan:
		// channel already closed, do nothing
	default:
		close(stopChan)
	}
}

// ctrl+c
func handleGracefulShutdown(stopChan chan struct{}) {
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interruptChan
		fmt.Fprintln(os.Stderr, "\nCtrl+C pressed. Shutting down...")
		closeStopChannel(stopChan)
	}()
}

func setNumThreads(userThreads int) int {
	if userThreads <= 0 || userThreads > runtime.NumCPU() {
		return runtime.NumCPU()
	}
	return userThreads
}

func isAllHashesCracked(hashes []YescryptHash) bool {
	for i := range hashes {
		if atomic.LoadInt32(&hashes[i].Cracked) == 0 {
			return false
		}
	}
	return true
}

func normalizeGPUArgs(args []string) []string {
	if len(args) <= 1 {
		return args
	}

	out := make([]string, 0, len(args))
	out = append(out, args[0])

	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg != "-gpu" && arg != "--gpu" {
			out = append(out, arg)
			continue
		}

		value := "all"
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			i++
		}
		out = append(out, "-gpu="+value)
	}

	return out
}

func countWordlistLines(path string) (uint64, error) {
	return countWordlistLinesStop(path, nil)
}

func countWordlistLinesStop(path string, stopChan <-chan struct{}) (uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// 16 MiB keeps syscall overhead small without consuming excessive RAM
	buf := make([]byte, 16*1024*1024)
	var lines uint64
	var last byte
	var readAny bool

	for {
		select {
		case <-stopChan:
			return 0, errWordlistCountCancelled
		default:
		}

		n, err := file.Read(buf)
		if n > 0 {
			readAny = true
			lines += uint64(bytes.Count(buf[:n], newlineSeparator))
			last = buf[n-1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}

	if readAny && last != '\n' {
		lines++
	}
	return lines, nil
}

func formatDuration(d time.Duration) string {
	return formatDurationMinutes(d, false)
}

func formatETADuration(d time.Duration) string {
	return formatDurationMinutes(d, true)
}

func formatDurationMinutes(d time.Duration, roundUp bool) string {
	if d < 0 {
		d = 0
	}

	totalMinutes := uint64(d / time.Minute)
	if roundUp && d%time.Minute != 0 {
		totalMinutes++
	}

	days := totalMinutes / (24 * 60)
	hours := (totalMinutes / 60) % 24
	minutes := totalMinutes % 60

	if days > 0 {
		return fmt.Sprintf("%02dd:%02dh:%02dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%02dh:%02dm", hours, minutes)
	}
	return fmt.Sprintf("%02dm", minutes)
}

func estimateRemainingDuration(linesProcessed, totalLines uint64, candidateRate float64) (time.Duration, bool) {
	if linesProcessed >= totalLines {
		return 0, true
	}
	if candidateRate <= 0 {
		return 0, false
	}

	remaining := float64(totalLines-linesProcessed) / candidateRate
	return time.Duration(remaining * float64(time.Second)), true
}

func estimateRemainingTime(linesProcessed, totalLines uint64, candidateRate float64) string {
	remaining, ok := estimateRemainingDuration(linesProcessed, totalLines, candidateRate)
	if !ok {
		return "--"
	}
	return formatETADuration(remaining)
}
