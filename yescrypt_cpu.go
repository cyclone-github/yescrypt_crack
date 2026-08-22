package main

// CPU fallback implementation adapted from Solar Designer's openwall/yescrypt-go
// native yescrypt path. See THIRD_PARTY_NOTICES.md for attribution and license details.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

const maxInt = int(^uint(0) >> 1)

func pbkdf2SHA256One(password, salt []byte, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	out := make([]byte, 0, keyLen)
	var ctr [4]byte
	for block := uint32(1); len(out) < keyLen; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		binary.BigEndian.PutUint32(ctr[:], block)
		_, _ = mac.Write(ctr[:])
		u := mac.Sum(nil)
		remain := keyLen - len(out)
		if remain < len(u) {
			u = u[:remain]
		}
		out = append(out, u...)
	}
	return out
}

func ycBlockCopy(dst, src []uint64, n int) { copy(dst, src[:n]) }

func ycBlockXOR(dst, src []uint64, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func ycSalsaXOR(tmp *[8]uint64, in, out []uint64, rounds int) {
	d0 := tmp[0] ^ in[0]
	d1 := tmp[1] ^ in[1]
	d2 := tmp[2] ^ in[2]
	d3 := tmp[3] ^ in[3]
	d4 := tmp[4] ^ in[4]
	d5 := tmp[5] ^ in[5]
	d6 := tmp[6] ^ in[6]
	d7 := tmp[7] ^ in[7]

	x0, x1 := uint32(d0), uint32(d6>>32)
	x2, x3 := uint32(d5), uint32(d3>>32)
	x4, x5 := uint32(d2), uint32(d0>>32)
	x6, x7 := uint32(d7), uint32(d5>>32)
	x8, x9 := uint32(d4), uint32(d2>>32)
	x10, x11 := uint32(d1), uint32(d7>>32)
	x12, x13 := uint32(d6), uint32(d4>>32)
	x14, x15 := uint32(d3), uint32(d1>>32)

	for i := 0; i < rounds; i += 2 {
		x4 ^= bits.RotateLeft32(x0+x12, 7)
		x8 ^= bits.RotateLeft32(x4+x0, 9)
		x12 ^= bits.RotateLeft32(x8+x4, 13)
		x0 ^= bits.RotateLeft32(x12+x8, 18)

		x9 ^= bits.RotateLeft32(x5+x1, 7)
		x13 ^= bits.RotateLeft32(x9+x5, 9)
		x1 ^= bits.RotateLeft32(x13+x9, 13)
		x5 ^= bits.RotateLeft32(x1+x13, 18)

		x14 ^= bits.RotateLeft32(x10+x6, 7)
		x2 ^= bits.RotateLeft32(x14+x10, 9)
		x6 ^= bits.RotateLeft32(x2+x14, 13)
		x10 ^= bits.RotateLeft32(x6+x2, 18)

		x3 ^= bits.RotateLeft32(x15+x11, 7)
		x7 ^= bits.RotateLeft32(x3+x15, 9)
		x11 ^= bits.RotateLeft32(x7+x3, 13)
		x15 ^= bits.RotateLeft32(x11+x7, 18)

		x1 ^= bits.RotateLeft32(x0+x3, 7)
		x2 ^= bits.RotateLeft32(x1+x0, 9)
		x3 ^= bits.RotateLeft32(x2+x1, 13)
		x0 ^= bits.RotateLeft32(x3+x2, 18)

		x6 ^= bits.RotateLeft32(x5+x4, 7)
		x7 ^= bits.RotateLeft32(x6+x5, 9)
		x4 ^= bits.RotateLeft32(x7+x6, 13)
		x5 ^= bits.RotateLeft32(x4+x7, 18)

		x11 ^= bits.RotateLeft32(x10+x9, 7)
		x8 ^= bits.RotateLeft32(x11+x10, 9)
		x9 ^= bits.RotateLeft32(x8+x11, 13)
		x10 ^= bits.RotateLeft32(x9+x8, 18)

		x12 ^= bits.RotateLeft32(x15+x14, 7)
		x13 ^= bits.RotateLeft32(x12+x15, 9)
		x14 ^= bits.RotateLeft32(x13+x12, 13)
		x15 ^= bits.RotateLeft32(x14+x13, 18)
	}

	d0 = uint64(uint32(d0)+x0) | uint64(uint32(d0>>32)+x5)<<32
	d1 = uint64(uint32(d1)+x10) | uint64(uint32(d1>>32)+x15)<<32
	d2 = uint64(uint32(d2)+x4) | uint64(uint32(d2>>32)+x9)<<32
	d3 = uint64(uint32(d3)+x14) | uint64(uint32(d3>>32)+x3)<<32
	d4 = uint64(uint32(d4)+x8) | uint64(uint32(d4>>32)+x13)<<32
	d5 = uint64(uint32(d5)+x2) | uint64(uint32(d5>>32)+x7)<<32
	d6 = uint64(uint32(d6)+x12) | uint64(uint32(d6>>32)+x1)<<32
	d7 = uint64(uint32(d7)+x6) | uint64(uint32(d7>>32)+x11)<<32

	out[0], tmp[0] = d0, d0
	out[1], tmp[1] = d1, d1
	out[2], tmp[2] = d2, d2
	out[3], tmp[3] = d3, d3
	out[4], tmp[4] = d4, d4
	out[5], tmp[5] = d5, d5
	out[6], tmp[6] = d6, d6
	out[7], tmp[7] = d7, d7
}

func ycBlockMix(tmp *[8]uint64, in, out []uint64, r int) {
	ycBlockCopy(tmp[:], in[(2*r-1)*8:], 8)
	for i := 0; i < 2*r; i += 2 {
		ycSalsaXOR(tmp, in[i*8:], out[i*4:], 8)
		ycSalsaXOR(tmp, in[i*8+8:], out[i*4+r*8:], 8)
	}
}

const (
	ycPWXsimple = 2
	ycPWXgather = 4
	ycPWXrounds = 6
	ycSwidth    = 8
	ycPWXbytes  = ycPWXgather * ycPWXsimple * 8
	ycPWXwords  = ycPWXbytes / 8
	ycSbytes    = 3 * (1 << ycSwidth) * ycPWXsimple * 8
	ycSwords    = ycSbytes / 8
	ycSmask     = (((1 << ycSwidth) - 1) * ycPWXsimple * 8)
)

type ycPwxformCtx struct {
	S0, S1, S2 []uint64
	w          uint32
}

func ycPwxform(X *[ycPWXwords]uint64, ctx *ycPwxformCtx) {
	S0, S1, S2, w := ctx.S0, ctx.S1, ctx.S2, ctx.w
	for i := 0; i < ycPWXrounds; i++ {
		for j := 0; j < ycPWXgather; j++ {
			x := X[j*ycPWXsimple]
			xl := uint32(x)
			xh := uint32(x >> 32)
			x = uint64(xh) * uint64(xl)
			xl = (xl & ycSmask) / 8
			xh = (xh & ycSmask) / 8
			x = (x + S0[xl]) ^ S1[xh]
			X[j*ycPWXsimple] = x

			y := X[j*ycPWXsimple+1]
			y = ((y>>32)*uint64(uint32(y)) + S0[xl+1]) ^ S1[xh+1]
			X[j*ycPWXsimple+1] = y

			if i != 0 && i != ycPWXrounds-1 {
				S2[w] = x
				S2[w+1] = y
				w += 2
			}
		}
	}
	ctx.S0, ctx.S1, ctx.S2 = S2, S0, S1
	ctx.w = w & ((1<<ycSwidth)*ycPWXsimple - 1)
}

func ycBlockMixPwxform(X *[ycPWXwords]uint64, B []uint64, r int, ctx *ycPwxformCtx) {
	r1 := 128 * r / ycPWXbytes
	ycBlockCopy(X[:], B[(r1-1)*ycPWXwords:], ycPWXwords)
	for i := 0; i < r1; i++ {
		ycBlockXOR(X[:], B[i*ycPWXwords:], ycPWXwords)
		ycPwxform(X, ctx)
		ycBlockCopy(B[i*ycPWXwords:], X[:], ycPWXwords)
	}
	i := (r1 - 1) * ycPWXbytes / 64
	*X = [ycPWXwords]uint64{}
	ycSalsaXOR(X, B[i*ycPWXwords:], B[i*ycPWXwords:], 2)
}

func ycInteger(b []uint64, r int) uint32 {
	return uint32(b[(2*r-1)*8])
}

func ycP2floor(x uint32) uint32 {
	for x&(x-1) != 0 {
		x &= x - 1
	}
	return x
}

func ycWrap(x, i uint32) uint32 {
	n := ycP2floor(i)
	return (x & (n - 1)) + (i - n)
}

func ycSmix(b []byte, r, N, Nloop int, v, xy []uint64, ctx *ycPwxformCtx) {
	var tmp [8]uint64
	R := 16 * r
	x := xy
	y := xy[R:]

	j := 0
	for i := 0; i < R; i++ {
		idx := (j & ^63) | ((j * 5) & 63)
		lo := binary.LittleEndian.Uint32(b[idx:])
		j += 4
		idx = (j & ^63) | ((j * 5) & 63)
		hi := binary.LittleEndian.Uint32(b[idx:])
		j += 4
		x[i] = uint64(lo) | uint64(hi)<<32
	}

	if ctx != nil {
		for i := 0; i < N; i++ {
			ycBlockCopy(v[i*R:], x, R)
			if i > 1 {
				jj := int(ycWrap(ycInteger(x, r), uint32(i)))
				ycBlockXOR(x, v[jj*R:], R)
			}
			ycBlockMixPwxform(&tmp, x, r, ctx)
		}
		for i := 0; i < Nloop; i++ {
			jj := int(ycInteger(x, r) & uint32(N-1))
			ycBlockXOR(x, v[jj*R:], R)
			ycBlockCopy(v[jj*R:], x, R)
			ycBlockMixPwxform(&tmp, x, r, ctx)
		}
	} else {
		for i := 0; i < N; i += 2 {
			ycBlockCopy(v[i*R:], x, R)
			ycBlockMix(&tmp, x, y, r)
			ycBlockCopy(v[(i+1)*R:], y, R)
			ycBlockMix(&tmp, y, x, r)
		}
		for i := 0; i < Nloop; i += 2 {
			jj := int(ycInteger(x, r) & uint32(N-1))
			ycBlockXOR(x, v[jj*R:], R)
			ycBlockMix(&tmp, x, y, r)
			jj = int(ycInteger(y, r) & uint32(N-1))
			ycBlockXOR(y, v[jj*R:], R)
			ycBlockMix(&tmp, y, x, r)
		}
	}

	j = 0
	for _, vv := range x[:R] {
		idx := (j & ^63) | ((j * 5) & 63)
		binary.LittleEndian.PutUint32(b[idx:], uint32(vv))
		j += 4
		idx = (j & ^63) | ((j * 5) & 63)
		binary.LittleEndian.PutUint32(b[idx:], uint32(vv>>32))
		j += 4
	}
}

func ycSmixYescrypt(b []byte, r, N int, v, xy []uint64, passwordSha256 []byte) {
	var ctx ycPwxformCtx
	var S [ycSwords]uint64
	ycSmix(b, 1, ycSbytes/128, 0, S[:], xy, nil)
	ctx.S2 = S[:]
	ctx.S1 = S[(1<<ycSwidth)*ycPWXsimple:]
	ctx.S0 = S[(1<<ycSwidth)*ycPWXsimple*2:]

	h := hmac.New(sha256.New, b[64*(2*r-1):])
	_, _ = h.Write(passwordSha256)
	copy(passwordSha256, h.Sum(nil))

	nloop := ((N+2)/3 + 1) & ^1
	ycSmix(b, r, N, nloop, v, xy, &ctx)
}

func yescryptKeyCPU(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("yescrypt: N must be > 1 and a power of 2")
	}
	if r <= 0 {
		return nil, errors.New("yescrypt: r must be > 0")
	}
	if p != 1 {
		return nil, errors.New("yescrypt: p must be 1")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("yescrypt: parameters are too large")
	}

	original := password
	ppassword := original
	pass := 1
	prehash := []byte("yescrypt-prehash")

	v := make([]uint64, 16*N*r)
	xy := make([]uint64, 16*max(r, 2))
	workN := N

	if workN/p >= 0x100 && workN/p*r >= 0x20000 {
		pass = 0
		workN >>= 6
	}

	var key []byte
	var pbuf [32]byte

	for pass <= 1 {
		if pass == 1 {
			prehash = prehash[:8]
		}
		h := hmac.New(sha256.New, prehash)
		_, _ = h.Write(ppassword)
		psum := h.Sum(nil)
		copy(pbuf[:], psum)
		ppassword = pbuf[:]

		b := pbkdf2SHA256One(ppassword, salt, p*128*r)
		copy(ppassword, b[:32])
		ycSmixYescrypt(b, r, workN, v, xy, ppassword)

		key = pbkdf2SHA256One(ppassword, b, max(keyLen, 32))
		if pass == 0 {
			copy(ppassword, key[:32])
			// Preserve the pass-0 result before pbuf is overwritten by the
			// next prehash operation.
			prev := make([]byte, 32)
			copy(prev, ppassword)
			ppassword = prev
			workN <<= 6
		} else {
			h1 := hmac.New(sha256.New, key[:32])
			_, _ = h1.Write([]byte("Client Key"))
			h2 := sha256.Sum256(h1.Sum(nil))
			copy(key, h2[:])
		}
		pass++
	}

	return key[:keyLen], nil
}
