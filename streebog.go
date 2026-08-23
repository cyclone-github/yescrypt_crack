package main

import (
	"crypto/hmac"
	"crypto/subtle"

	"github.com/tarantool/go-gostcrypto/streebog"
)

func streebog256(data []byte) ([32]byte, error) {
	return streebog.Sum256(data), nil
}

func hmacStreebog256(key, msg []byte) ([32]byte, error) {
	var out [32]byte
	mac := hmac.New(streebog.New256, key)
	_, _ = mac.Write(msg)
	copy(out[:], mac.Sum(nil))
	return out, nil
}

func gostFinalize(password, setting, yescryptDigest []byte) ([32]byte, error) {
	hk, err := streebog256(password)
	if err != nil {
		return [32]byte{}, err
	}
	interm, err := hmacStreebog256(hk[:], setting)
	if err != nil {
		return [32]byte{}, err
	}
	return hmacStreebog256(interm[:], yescryptDigest)
}

func constantTimeDigestEqual(a [32]byte, b []byte) bool {
	if len(b) != 32 {
		return false
	}
	return subtle.ConstantTimeCompare(a[:], b) == 1
}
