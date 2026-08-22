package main

import (
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	statsSampleInterval = time.Second
	rateEMAAlpha        = 0.15
	etaEMAAlpha         = 0.10
)

// monitor status
func monitorPrintStats(crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan <-chan struct{}, startTime time.Time, totalHashCount int, totalWordlistLines uint64, wg *sync.WaitGroup, interval int) {
	defer wg.Done()

	ticker := time.NewTicker(statsSampleInterval)
	defer ticker.Stop()

	lastSampleTime := startTime
	lastPrintTime := startTime
	var lastLines uint64
	var lastHashes uint64
	var candidateRateEMA float64
	var hashRateEMA float64
	var etaEMA time.Duration
	var candidateRateReady bool
	var hashRateReady bool
	var etaReady bool

	sample := func(now time.Time) {
		lines := atomic.LoadUint64(linesProcessed)
		hashes := atomic.LoadUint64(totalHashesGenerated)
		sampleDuration := now.Sub(lastSampleTime)

		if sampleDuration > 0 {
			candidateRate := calcSampleRate(lines, lastLines, sampleDuration)
			hashRate := calcSampleRate(hashes, lastHashes, sampleDuration)

			candidateRateEMA, candidateRateReady = updateRateEMA(candidateRateEMA, candidateRate, candidateRateReady, rateEMAAlpha)
			hashRateEMA, hashRateReady = updateRateEMA(hashRateEMA, hashRate, hashRateReady, rateEMAAlpha)

			if totalWordlistLines > 0 && candidateRateReady {
				if rawETA, ok := estimateRemainingDuration(lines, totalWordlistLines, candidateRateEMA); ok {
					etaEMA, etaReady = updateDurationEMA(etaEMA, rawETA, etaReady, etaEMAAlpha)
				}
			}
		}

		lastLines = lines
		lastHashes = hashes
		lastSampleTime = now
	}

	print := func(now time.Time) {
		lines := atomic.LoadUint64(linesProcessed)
		printStats(now.Sub(startTime), int(atomic.LoadInt32(crackedCount)), totalHashCount, lines, totalWordlistLines, hashRateEMA, hashRateReady, etaEMA, etaReady)
	}

	for {
		select {
		case <-stopChan:
			now := time.Now()
			sample(now)
			print(now)
			return
		case now := <-ticker.C:
			sample(now)
			if interval > 0 && now.Sub(lastPrintTime) >= time.Duration(interval)*time.Second {
				print(now)
				lastPrintTime = now
			}
		}
	}
}

func calcSampleRate(total, previous uint64, interval time.Duration) float64 {
	if interval <= 0 || total < previous {
		return 0
	}
	return float64(total-previous) / interval.Seconds()
}

func updateRateEMA(current, sample float64, initialized bool, alpha float64) (float64, bool) {
	if !initialized {
		if sample <= 0 {
			return current, false
		}
		return sample, true
	}
	return current + alpha*(sample-current), true
}

func updateDurationEMA(current, sample time.Duration, initialized bool, alpha float64) (time.Duration, bool) {
	if !initialized {
		return sample, true
	}
	return time.Duration(float64(current) + alpha*(float64(sample)-float64(current))), true
}

// printStats
func printStats(elapsedTime time.Duration, crackedCount int, totalHashCount int, linesProcessed, totalWordlistLines uint64, hashesPerSecond float64, hashRateReady bool, eta time.Duration, etaReady bool) {
	timeText := formatDuration(elapsedTime)

	// stdin has no known line count, so only elapsed time can be displayed
	if totalWordlistLines > 0 {
		switch {
		case linesProcessed >= totalWordlistLines:
			timeText += "/00m"
		case etaReady:
			timeText += "/" + formatETADuration(eta)
		default:
			timeText += "/--"
		}
	}

	if !hashRateReady {
		hashesPerSecond = 0
	}
	log.Printf("Cracked: %d/%d %.2f h/s %s", crackedCount, totalHashCount, hashesPerSecond, timeText)
}
