package main

import (
	"bytes"
	"crypto/hmac"

	"github.com/openwall/yescrypt-go"
	"github.com/tarantool/go-gostcrypto/streebog"
)

var cryptBase64DecodeTable = [...]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	64, 64, 64, 64, 64, 64, 64,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	64, 64, 64, 64, 64, 64,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
}

func cryptBase64Value(c byte) int {
	if c >= '.' && c <= 'z' {
		return int(cryptBase64DecodeTable[c-'.'])
	}
	return 64
}

// decodeCryptBase64 decodes the little-endian crypt(3) base64 encoding used
// by yescrypt and gost-yescrypt. It is not RFC 4648 base64.
func decodeCryptBase64(src []byte) []byte {
	dst := make([]byte, 0, len(src)*3/4)

	for i := 0; i < len(src); {
		var value uint32
		var bits uint32

		for ; bits < 24 && i < len(src); bits += 6 {
			c := cryptBase64Value(src[i])
			if c > 63 {
				return nil
			}
			i++
			value |= uint32(c) << bits
		}

		if bits < 12 {
			return nil
		}

		for ; bits >= 8; bits -= 8 {
			dst = append(dst, byte(value))
			value >>= 8
		}

		if value != 0 {
			return nil
		}
	}

	return dst
}

func crackGostYescrypt(password, fullHash []byte) bool {
	if !bytes.HasPrefix(fullHash, []byte("$gy$")) {
		return false
	}

	// libxcrypt computes the normal yescrypt result first using the same
	// parameters and salt. Convert "$gy$..." to "$y$..." for yescrypt-go.
	yescryptSetting := make([]byte, 0, len(fullHash)-1)
	yescryptSetting = append(yescryptSetting, '$', 'y', '$')
	yescryptSetting = append(yescryptSetting, fullHash[4:]...)

	yescryptHash, err := yescrypt.Hash(password, yescryptSetting)
	if err != nil {
		return false
	}

	yescryptDigestPos := bytes.LastIndexByte(yescryptHash, '$')
	if yescryptDigestPos < 0 {
		return false
	}
	yescryptDigest := decodeCryptBase64(yescryptHash[yescryptDigestPos+1:])
	if len(yescryptDigest) != 32 {
		return false
	}

	// the final '$' separates the gost-yescrypt setting from its digest
	// libxcrypt intentionally excludes this '$' from the inner HMAC message
	gostDigestPos := bytes.LastIndexByte(fullHash, '$')
	if gostDigestPos < 0 {
		return false
	}
	expectedDigest := decodeCryptBase64(fullHash[gostDigestPos+1:])
	if len(expectedDigest) != 32 {
		return false
	}

	// libxcrypt construction:
	//   hk      = Streebog-256(password)
	//   interm  = HMAC-Streebog-256(hk, gost setting without trailing '$')
	//   result  = HMAC-Streebog-256(interm, raw yescrypt 256-bit result)
	hk := streebog.Sum256(password)

	mac := hmac.New(streebog.New256, hk[:])
	_, _ = mac.Write(fullHash[:gostDigestPos])
	interm := mac.Sum(nil)

	mac = hmac.New(streebog.New256, interm)
	_, _ = mac.Write(yescryptDigest)
	generatedDigest := mac.Sum(nil)

	return hmac.Equal(expectedDigest, generatedDigest)
}
