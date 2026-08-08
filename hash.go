package main

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/openwall/yescrypt-go"
)

type YescryptHash struct {
	Hash    []byte
	Cracked int32
}

func ReadYescryptHashes(filePath string) ([]YescryptHash, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// accept native yescrypt ($y$) and gost-yescrypt ($gy$) hashes
	yescryptRegex := regexp.MustCompile(`^\$(y|gy)\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}$`)

	var hashes []YescryptHash
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// yescrypt / gost-yescrypt sanity check
		if !yescryptRegex.MatchString(line) {
			continue
		}

		hashes = append(hashes, YescryptHash{Hash: []byte(line), Cracked: 0})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

func crackHash(password, fullHash []byte) bool {
	switch {
	case bytes.HasPrefix(fullHash, []byte("$y$")):
		return crackYescrypt(password, fullHash)
	case bytes.HasPrefix(fullHash, []byte("$gy$")):
		return crackGostYescrypt(password, fullHash)
	default:
		return false
	}
}

func crackYescrypt(password, fullHash []byte) bool {
	generatedHash, err := yescrypt.Hash(password, fullHash)
	if err != nil {
		return false
	}
	return bytes.Equal(fullHash, generatedHash)
}
