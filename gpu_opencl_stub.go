//go:build !windows && (!linux || !cgo)

package main

import "errors"

const gpuMaxPasswordLen = 256

var (
	errGPUCancelled      = errors.New("GPU cancelled")
	errOpenCLUnsupported = errors.New("OpenCL GPU backend is unavailable in this build")
)

type GPUDeviceInfo struct {
	Index     int
	Name      string
	GlobalMem uint64
	MaxAlloc  uint64
}

type OpenCLGPU struct {
	Info     GPUDeviceInfo
	N        uint32
	R        uint32
	Capacity int
}

func ListOpenCLGPUs() ([]GPUDeviceInfo, error) {
	return nil, errOpenCLUnsupported
}

func NewOpenCLGPU(info GPUDeviceInfo) (*OpenCLGPU, error) {
	return nil, errOpenCLUnsupported
}

func (g *OpenCLGPU) Close()          {}
func (g *OpenCLGPU) Cancel()         {}
func (g *OpenCLGPU) ResetCancel()    {}
func (g *OpenCLGPU) SelfTest() error { return errOpenCLUnsupported }

func (g *OpenCLGPU) Configure(N, r uint32, batchHint int) (int, error) {
	return 0, errOpenCLUnsupported
}

func (g *OpenCLGPU) HashBatch(passwords [][]byte, salt []byte) ([][32]byte, error) {
	return nil, errOpenCLUnsupported
}
