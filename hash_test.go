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
)

const (
	testPassword      = "password"
	testYescrypt      = "$y$j9T$ukgaTIHHgVLdJH9qAK9Nz/$D6rr9OXstjx/QksjwzcO2M2UYgO.98RNVWt9jw1aW/9"
	testGostYescrypt  = "$gy$j9T$ukgaTIHHgVLdJH9qAK9Nz/$bH5kn7UF0Sk8ZgVzI6HWILrRemSMLVyJTiZgWbASi83"
	testGostYescrypt2 = "$gy$jAT$0123456789abcdef0123456789abcdef$nhEOJFlM.wasdffY0jRHd0ACl2sH.1CuV0kREkGTKM8"
)

func TestCrackHashDispatch(t *testing.T) {
	password := []byte(testPassword)

	if !crackHash(password, []byte(testYescrypt)) {
		t.Fatal("yescrypt test vector did not match")
	}
	if !crackHash(password, []byte(testGostYescrypt)) {
		t.Fatal("gost-yescrypt test vector did not match")
	}
	if !crackHash([]byte("hunter2"), []byte(testGostYescrypt2)) {
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
	var linesProcessed int32
	var totalHashesGenerated int32
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
	if got := atomic.LoadInt32(&linesProcessed); got != 1 {
		t.Fatalf("expected one wordlist candidate to be processed, got %d", got)
	}
	if got := atomic.LoadInt32(&totalHashesGenerated); got != 2 {
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
