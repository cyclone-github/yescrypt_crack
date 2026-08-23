package main

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
)

type HashKind uint8

const (
	HashYescrypt HashKind = iota + 1
	HashGostYescrypt
)

type YescryptHash struct {
	Hash     []byte
	Cracked  int32
	Kind     HashKind
	Params   string
	Salt     []byte
	Expected [32]byte
	N        uint32
	R        uint32
	GPUOK    bool
	Setting  []byte
}

func parseYescryptHash(line string) (YescryptHash, error) {
	var out YescryptHash
	parts := strings.Split(line, "$")
	if len(parts) != 5 || parts[0] != "" {
		return out, fmt.Errorf("bad field count")
	}
	switch parts[1] {
	case "y":
		out.Kind = HashYescrypt
	case "gy":
		out.Kind = HashGostYescrypt
	default:
		return out, fmt.Errorf("unsupported signature")
	}
	if parts[2] == "" || len(parts[3]) > 86 || len(parts[4]) != 43 {
		return out, fmt.Errorf("bad yescrypt field length")
	}

	salt := decodeCryptBase64([]byte(parts[3]))
	if salt == nil || len(salt) > 64 {
		return out, fmt.Errorf("bad salt encoding")
	}
	digest := decodeCryptBase64([]byte(parts[4]))
	if len(digest) != 32 {
		return out, fmt.Errorf("bad digest encoding")
	}

	out.Hash = []byte(line)
	out.Params = parts[2]
	out.Salt = salt
	copy(out.Expected[:], digest)
	last := strings.LastIndexByte(line, '$')
	out.Setting = []byte(line[:last])

	if len(out.Params) == 3 && out.Params[0] == 'j' {
		nlog := cryptBase64Value(out.Params[1]) + 1
		r := cryptBase64Value(out.Params[2]) + 1
		if nlog >= 10 && nlog <= 18 && r >= 1 && r <= 32 {
			out.N = 1 << uint(nlog)
			out.R = uint32(r)
			out.GPUOK = true
		}
	}
	return out, nil
}

func ReadYescryptHashes(filePath string) ([]YescryptHash, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var hashes []YescryptHash
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		h, err := parseYescryptHash(line)
		if err != nil {
			continue
		}
		hashes = append(hashes, h)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

func crackHash(password, fullHash []byte) bool {
	h, err := parseYescryptHash(string(fullHash))
	if err != nil {
		return false
	}
	return crackParsedHashCPU(password, &h)
}

func crackParsedHashCPU(password []byte, h *YescryptHash) bool {
	if !h.GPUOK {
		if len(h.Hash) != 0 {
			parsed, err := parseYescryptHash(string(h.Hash))
			if err == nil && parsed.GPUOK {
				return crackParsedHashCPU(password, &parsed)
			}
		}
		return false
	}
	digest, err := yescryptKeyCPU(password, h.Salt, int(h.N), int(h.R), 1, 32)
	if err != nil {
		return false
	}
	if h.Kind == HashYescrypt {
		return subtle.ConstantTimeCompare(digest, h.Expected[:]) == 1
	}
	generated, err := gostFinalize(password, h.Setting, digest)
	if err != nil {
		return false
	}
	return constantTimeDigestEqual(generated, h.Expected[:])
}
