//go:build linux && cgo

package main

/*
#cgo LDFLAGS: -ldl
#include <stdlib.h>
#include "gpu_opencl.h"
*/
import "C"

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

//go:embed kernels/yescrypt.cl
var yescryptOpenCLSource string

const gpuMaxPasswordLen = 256

var errGPUCancelled = errors.New("GPU cancelled")

type GPUDeviceInfo struct {
	Index     int
	Name      string
	GlobalMem uint64
	MaxAlloc  uint64
}

func cErrorString(buf *[8192]C.char) string {
	if buf[0] == 0 {
		return "unknown OpenCL error"
	}
	return C.GoString(&buf[0])
}

func ListOpenCLGPUs() ([]GPUDeviceInfo, error) {
	var errbuf [8192]C.char
	n := int(C.ycl_opencl_device_count(&errbuf[0], C.size_t(len(errbuf))))
	if n < 0 {
		return nil, errors.New(cErrorString(&errbuf))
	}
	out := make([]GPUDeviceInfo, 0, n)
	for i := 0; i < n; i++ {
		var name [512]C.char
		var gm, ma C.uint64_t
		for j := range errbuf {
			errbuf[j] = 0
		}
		if C.ycl_opencl_device_info(C.int(i), &name[0], C.size_t(len(name)), &gm, &ma, &errbuf[0], C.size_t(len(errbuf))) != 0 {
			return nil, errors.New(cErrorString(&errbuf))
		}
		out = append(out, GPUDeviceInfo{Index: i, Name: C.GoString(&name[0]), GlobalMem: uint64(gm), MaxAlloc: uint64(ma)})
	}
	return out, nil
}

type OpenCLGPU struct {
	ctx      *C.ycl_gpu_ctx
	Info     GPUDeviceInfo
	N        uint32
	R        uint32
	Capacity int
}

func NewOpenCLGPU(info GPUDeviceInfo) (*OpenCLGPU, error) {
	src := []byte(yescryptOpenCLSource)
	if len(src) == 0 {
		return nil, errors.New("embedded OpenCL kernel is empty")
	}
	p := C.CBytes(src)
	defer C.free(p)
	var errbuf [8192]C.char
	ctx := C.ycl_gpu_create(C.int(info.Index), (*C.char)(p), C.size_t(len(src)), &errbuf[0], C.size_t(len(errbuf)))
	if ctx == nil {
		return nil, errors.New(cErrorString(&errbuf))
	}
	return &OpenCLGPU{ctx: ctx, Info: info}, nil
}

func (g *OpenCLGPU) Close() {
	if g != nil && g.ctx != nil {
		C.ycl_gpu_destroy(g.ctx)
		g.ctx = nil
	}
}

func (g *OpenCLGPU) Cancel() {
	if g != nil && g.ctx != nil {
		C.ycl_gpu_cancel(g.ctx)
	}
}

func (g *OpenCLGPU) ResetCancel() {
	if g != nil && g.ctx != nil {
		C.ycl_gpu_reset_cancel(g.ctx)
	}
}

func (g *OpenCLGPU) SelfTest() error {
	const vector = "$y$j9T$Gg3nKTjUa.Hrq3ZPL9S9J0$kJBFNrOZC2sCjYIOV3G4/NTOOFWUULJDthOnxtiTez9"
	h, err := parseYescryptHash(vector)
	if err != nil {
		return fmt.Errorf("internal GPU self-test vector parse failed: %w", err)
	}
	if _, err := g.Configure(h.N, h.R, 1); err != nil {
		return fmt.Errorf("GPU self-test configure failed: %w", err)
	}
	out, err := g.HashBatch([][]byte{[]byte("password")}, h.Salt)
	if err != nil {
		return fmt.Errorf("GPU self-test execution failed: %w", err)
	}
	if len(out) != 1 || !bytes.Equal(out[0][:], h.Expected[:]) {
		if len(out) == 1 {
			return fmt.Errorf("GPU self-test digest mismatch: got %x want %x", out[0], h.Expected)
		}
		return fmt.Errorf("GPU self-test returned %d digests", len(out))
	}
	return nil
}

func (g *OpenCLGPU) Configure(N, r uint32, batchHint int) (int, error) {
	if g == nil || g.ctx == nil {
		return 0, errors.New("GPU context is closed")
	}
	if batchHint < 0 {
		batchHint = 0
	}
	var cap C.uint32_t
	var errbuf [8192]C.char
	if C.ycl_gpu_configure(g.ctx, C.uint32_t(N), C.uint32_t(r), C.uint32_t(batchHint), &cap, &errbuf[0], C.size_t(len(errbuf))) != 0 {
		return 0, errors.New(cErrorString(&errbuf))
	}
	g.N, g.R, g.Capacity = N, r, int(cap)
	return g.Capacity, nil
}

func (g *OpenCLGPU) HashBatch(passwords [][]byte, salt []byte) ([][32]byte, error) {
	if g == nil || g.ctx == nil || g.Capacity == 0 {
		return nil, errors.New("GPU not configured")
	}
	if len(passwords) == 0 {
		return nil, nil
	}
	if len(passwords) > g.Capacity {
		return nil, fmt.Errorf("GPU batch %d exceeds configured capacity %d", len(passwords), g.Capacity)
	}
	if len(salt) > 64 {
		return nil, fmt.Errorf("GPU salt length %d exceeds 64 bytes", len(salt))
	}

	packed := make([]byte, len(passwords)*gpuMaxPasswordLen)
	lens := make([]uint32, len(passwords))
	for i, pw := range passwords {
		if len(pw) > gpuMaxPasswordLen {
			return nil, fmt.Errorf("password %d is %d bytes; GPU limit is %d", i, len(pw), gpuMaxPasswordLen)
		}
		copy(packed[i*gpuMaxPasswordLen:], pw)
		lens[i] = uint32(len(pw))
	}
	rawOut := make([]byte, len(passwords)*32)
	var saltPtr *C.uchar
	if len(salt) != 0 {
		saltPtr = (*C.uchar)(unsafe.Pointer(&salt[0]))
	}
	var errbuf [8192]C.char
	rc := C.ycl_gpu_hash(
		g.ctx,
		(*C.uchar)(unsafe.Pointer(&packed[0])),
		(*C.uint32_t)(unsafe.Pointer(&lens[0])),
		C.uint32_t(len(passwords)),
		saltPtr,
		C.uint32_t(len(salt)),
		(*C.uchar)(unsafe.Pointer(&rawOut[0])),
		&errbuf[0], C.size_t(len(errbuf)),
	)
	runtime.KeepAlive(packed)
	runtime.KeepAlive(lens)
	runtime.KeepAlive(salt)
	if rc == C.YCL_GPU_CANCELLED {
		return nil, errGPUCancelled
	}
	if rc != 0 {
		return nil, errors.New(cErrorString(&errbuf))
	}
	out := make([][32]byte, len(passwords))
	for i := range out {
		copy(out[i][:], rawOut[i*32:(i+1)*32])
	}
	return out, nil
}
