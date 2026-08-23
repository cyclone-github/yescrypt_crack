package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testPassword      = "password"
	testYescrypt      = "$y$j9T$Gg3nKTjUa.Hrq3ZPL9S9J0$kJBFNrOZC2sCjYIOV3G4/NTOOFWUULJDthOnxtiTez9"
	testGostYescrypt  = "$gy$j9T$Gg3nKTjUa.Hrq3ZPL9S9J0$NoLVpQb1ewFIXSN.3PShWUybuC8xZJ8HER18hi7lU73"
	testGostYescrypt2 = "$gy$jAT$XDfTHhSYsW86PT.3V3l.UVh.yTta/MEA$gTqcPPYO9SMD3p0K0e0jHic0nwVNNFEgM01pftAVfdB"
)

func TestCrackHashDispatch(t *testing.T) {
	password := []byte(testPassword)

	if !crackHash(password, []byte(testYescrypt)) {
		t.Fatal("yescrypt test vector did not match")
	}
	if !crackHash(password, []byte(testGostYescrypt)) {
		t.Fatal("gost-yescrypt test vector did not match")
	}
	if !crackHash(password, []byte(testGostYescrypt2)) {
		t.Fatal("second gost-yescrypt test vector did not match")
	}
	if crackHash([]byte("wrong-password"), []byte(testGostYescrypt)) {
		t.Fatal("gost-yescrypt matched an incorrect password")
	}
}

func TestReadYescryptHashesMixed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashes.txt")
	data := testYescrypt + "\n" + testGostYescrypt + "\n$6$not-supported\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	hashes, err := ReadYescryptHashes(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 {
		t.Fatalf("expected 2 supported hashes, got %d", len(hashes))
	}
}

func TestProcessPasswordChecksAllUncrackedHashes(t *testing.T) {
	hashes := []YescryptHash{
		{Hash: []byte(testYescrypt)},
		{Hash: []byte(testGostYescrypt)},
	}

	var output bytes.Buffer
	writer := bufio.NewWriter(&output)
	var writerMu sync.Mutex
	var crackedCount int32
	var linesProcessed uint64
	var totalHashesGenerated uint64
	stopChan := make(chan struct{})

	processPassword(
		[]byte(testPassword),
		hashes,
		&writerMu,
		writer,
		&crackedCount,
		&linesProcessed,
		&totalHashesGenerated,
		stopChan,
	)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}

	if got := atomic.LoadInt32(&crackedCount); got != 2 {
		t.Fatalf("expected one plaintext to crack both hashes, got %d/2", got)
	}
	if atomic.LoadInt32(&hashes[0].Cracked) != 1 || atomic.LoadInt32(&hashes[1].Cracked) != 1 {
		t.Fatalf("expected both hashes to be marked cracked: %+v", hashes)
	}
	if got := atomic.LoadUint64(&linesProcessed); got != 1 {
		t.Fatalf("expected one wordlist candidate to be processed, got %d", got)
	}
	if got := atomic.LoadUint64(&totalHashesGenerated); got != 2 {
		t.Fatalf("expected candidate to be tested against both hashes, got %d hash attempts", got)
	}
	if got := strings.Count(output.String(), ":password\n"); got != 2 {
		t.Fatalf("expected two cracked output lines for the same plaintext, got %d; output=%q", got, output.String())
	}

	select {
	case <-stopChan:
		// Expected: both hashes were cracked by the same candidate.
	default:
		t.Fatal("expected stop channel to close after all hashes were cracked")
	}
}

func TestCPUKeyMatchesKnownYescryptDigest(t *testing.T) {
	h, err := parseYescryptHash(testYescrypt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := yescryptKeyCPU([]byte(testPassword), h.Salt, int(h.N), int(h.R), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, h.Expected[:]) {
		t.Fatalf("raw yescrypt mismatch: got %x want %x", got, h.Expected)
	}
}

func TestGostFinalizeKnownVector(t *testing.T) {
	gy, err := parseYescryptHash(testGostYescrypt)
	if err != nil {
		t.Fatal(err)
	}
	y, err := parseYescryptHash(testYescrypt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := gostFinalize([]byte(testPassword), gy.Setting, y.Expected[:])
	if err != nil {
		t.Fatal(err)
	}
	if !constantTimeDigestEqual(got, gy.Expected[:]) {
		t.Fatalf("gost finalization mismatch: got %x want %x", got, gy.Expected)
	}
}

func TestGPUCapacityJ9T24GiB(t *testing.T) {
	info := GPUDeviceInfo{GlobalMem: 24 << 30, MaxAlloc: 6 << 30}
	cap := estimateGPUCapacity(info, 4096, 32, 0)
	if cap != 1280 {
		t.Fatalf("expected tuned j9T auto batch 1280 on a 24GiB/6GiB-allocation GPU, got %d", cap)
	}

	manual := estimateGPUCapacity(info, 4096, 32, 1352)
	if manual != 1352 {
		t.Fatalf("expected explicit GPU batch 1352 to be preserved, got %d", manual)
	}
}

func TestTuneAutoGPUCapacity4090(t *testing.T) {
	if got := tuneAutoGPUCapacity(1352); got != 1280 {
		t.Fatalf("expected measured 4090 cap 1352 to tune to 1280, got %d", got)
	}
}

func TestNormalizeGPUArgs(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{[]string{"yescrypt_crack.bin", "-gpu", "-h", "hashes.txt"}, []string{"yescrypt_crack.bin", "-gpu=all", "-h", "hashes.txt"}},
		{[]string{"yescrypt_crack.bin", "-gpu", "0,1", "-h", "hashes.txt"}, []string{"yescrypt_crack.bin", "-gpu=0,1", "-h", "hashes.txt"}},
		{[]string{"yescrypt_crack.bin", "-gpu", "list"}, []string{"yescrypt_crack.bin", "-gpu=list"}},
	}

	for _, tc := range tests {
		got := normalizeGPUArgs(tc.in)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Fatalf("normalizeGPUArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCountWordlistLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree"), 0600); err != nil {
		t.Fatal(err)
	}

	lines, err := countWordlistLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines != 3 {
		t.Fatalf("expected 3 wordlist lines, got %d", lines)
	}
}

func TestEstimateRemainingTime(t *testing.T) {
	if got := estimateRemainingTime(500, 1000, 100); got != "01m" {
		t.Fatalf("expected sub-minute ETA to round up to 01m, got %q", got)
	}
	if got := estimateRemainingTime(1000, 1000, 100); got != "00m" {
		t.Fatalf("expected completed ETA, got %q", got)
	}
}

func TestFormatDurationMinutes(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{10 * time.Second, "00m"},
		{time.Minute, "01m"},
		{3*time.Hour + 7*time.Minute, "03h:07m"},
		{156*24*time.Hour + 7*time.Hour + 6*time.Minute, "156d:07h:06m"},
	}
	for _, tc := range tests {
		if got := formatDuration(tc.d); got != tc.want {
			t.Fatalf("formatDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}
