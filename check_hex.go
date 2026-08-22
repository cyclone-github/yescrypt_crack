package main

import (
	"bytes"
	"encoding/hex"
)

// dehex wordlist line
/* note:
the checkForHexBytes() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
*/
func checkForHexBytes(line []byte) ([]byte, []byte, int) {
	hexPrefix := []byte("$HEX[")
	suffix := byte(']')

	if bytes.HasPrefix(line, hexPrefix) {
		var hexErrorDetected int
		if line[len(line)-1] != suffix {
			line = append(line, suffix)
			hexErrorDetected = 1
		}

		startIdx := bytes.IndexByte(line, '[')
		endIdx := bytes.LastIndexByte(line, ']')
		if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
			return line, line, 1
		}
		hexContent := line[startIdx+1 : endIdx]

		decodedBytes := make([]byte, hex.DecodedLen(len(hexContent)))
		n, err := hex.Decode(decodedBytes, hexContent)
		if err != nil {
			cleaned := make([]byte, 0, len(hexContent))
			for _, b := range hexContent {
				if ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F') {
					cleaned = append(cleaned, b)
				}
			}
			if len(cleaned)%2 != 0 {
				cleaned = append([]byte{'0'}, cleaned...)
			}

			decodedBytes = make([]byte, hex.DecodedLen(len(cleaned)))
			n, err = hex.Decode(decodedBytes, cleaned)
			if err != nil {
				return line, line, 1
			}
			hexErrorDetected = 1
		}
		decodedBytes = decodedBytes[:n]
		return decodedBytes, hexContent, hexErrorDetected
	}
	return line, line, 0
}
