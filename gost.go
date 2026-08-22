package main

var cryptBase64DecodeTable = [...]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	64, 64, 64, 64, 64, 64, 64,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	64, 64, 64, 64, 64, 64,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
}

const cryptBase64Alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

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

func encodeCryptBase64(src []byte) []byte {
	dst := make([]byte, 0, (len(src)*8+5)/6)
	for i := 0; i < len(src); {
		var value uint32
		bits := 0
		for bits < 24 && i < len(src) {
			value |= uint32(src[i]) << bits
			i++
			bits += 8
		}
		for bits > 0 {
			dst = append(dst, cryptBase64Alphabet[value&0x3f])
			value >>= 6
			bits -= 6
		}
	}
	return dst
}

func crackGostYescrypt(password, fullHash []byte) bool {
	return crackHash(password, fullHash)
}
