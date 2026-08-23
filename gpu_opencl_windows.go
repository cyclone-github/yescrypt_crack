//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
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

const (
	clSuccess               int32  = 0
	clDeviceNotFound        int32  = -1
	clPlatformNotFoundKHR   int32  = -1001
	clDeviceTypeGPU         uint64 = 1 << 2
	clDeviceName            uint32 = 0x102B
	clDeviceGlobalMemSize   uint32 = 0x101F
	clDeviceMaxMemAllocSize uint32 = 0x1010
	clProgramBuildLog       uint32 = 0x1183
	clMemReadWrite          uint64 = 1 << 0
	clMemWriteOnly          uint64 = 1 << 1
	clMemReadOnly           uint64 = 1 << 2
	clFalse                 uint32 = 0
	clTrue                  uint32 = 1
	windowsMaxGPUDevices           = 32
	windowsMaxR                    = 32
	windowsSWords                  = 1536
	windowsOneMiB           uint64 = 1024 * 1024
)

type openCLWinAPI struct {
	dll                       *syscall.DLL
	clGetPlatformIDs          *syscall.Proc
	clGetDeviceIDs            *syscall.Proc
	clGetDeviceInfo           *syscall.Proc
	clCreateContext           *syscall.Proc
	clReleaseContext          *syscall.Proc
	clCreateCommandQueue      *syscall.Proc
	clReleaseCommandQueue     *syscall.Proc
	clCreateBuffer            *syscall.Proc
	clReleaseMemObject        *syscall.Proc
	clCreateProgramWithSource *syscall.Proc
	clBuildProgram            *syscall.Proc
	clGetProgramBuildInfo     *syscall.Proc
	clReleaseProgram          *syscall.Proc
	clCreateKernel            *syscall.Proc
	clReleaseKernel           *syscall.Proc
	clSetKernelArg            *syscall.Proc
	clEnqueueWriteBuffer      *syscall.Proc
	clEnqueueReadBuffer       *syscall.Proc
	clEnqueueNDRangeKernel    *syscall.Proc
	clFinish                  *syscall.Proc
}

var (
	openCLWinOnce sync.Once
	openCLWin     *openCLWinAPI
	openCLWinErr  error
)

func loadOpenCLWin() (*openCLWinAPI, error) {
	openCLWinOnce.Do(func() {
		dll, err := syscall.LoadDLL("OpenCL.dll")
		if err != nil {
			openCLWinErr = fmt.Errorf("OpenCL loader not found: %w", err)
			return
		}

		a := &openCLWinAPI{dll: dll}
		lookups := []struct {
			name string
			dst  **syscall.Proc
		}{
			{"clGetPlatformIDs", &a.clGetPlatformIDs},
			{"clGetDeviceIDs", &a.clGetDeviceIDs},
			{"clGetDeviceInfo", &a.clGetDeviceInfo},
			{"clCreateContext", &a.clCreateContext},
			{"clReleaseContext", &a.clReleaseContext},
			{"clCreateCommandQueue", &a.clCreateCommandQueue},
			{"clReleaseCommandQueue", &a.clReleaseCommandQueue},
			{"clCreateBuffer", &a.clCreateBuffer},
			{"clReleaseMemObject", &a.clReleaseMemObject},
			{"clCreateProgramWithSource", &a.clCreateProgramWithSource},
			{"clBuildProgram", &a.clBuildProgram},
			{"clGetProgramBuildInfo", &a.clGetProgramBuildInfo},
			{"clReleaseProgram", &a.clReleaseProgram},
			{"clCreateKernel", &a.clCreateKernel},
			{"clReleaseKernel", &a.clReleaseKernel},
			{"clSetKernelArg", &a.clSetKernelArg},
			{"clEnqueueWriteBuffer", &a.clEnqueueWriteBuffer},
			{"clEnqueueReadBuffer", &a.clEnqueueReadBuffer},
			{"clEnqueueNDRangeKernel", &a.clEnqueueNDRangeKernel},
			{"clFinish", &a.clFinish},
		}
		for _, lookup := range lookups {
			proc, err := dll.FindProc(lookup.name)
			if err != nil {
				_ = dll.Release()
				openCLWinErr = fmt.Errorf("OpenCL symbol %s missing: %w", lookup.name, err)
				return
			}
			*lookup.dst = proc
		}
		openCLWin = a
	})
	if openCLWinErr != nil {
		return nil, openCLWinErr
	}
	return openCLWin, nil
}

func clStatus(p *syscall.Proc, args ...uintptr) int32 {
	r1, _, _ := p.Call(args...)
	return int32(r1)
}

func ptr(v unsafe.Pointer) uintptr { return uintptr(v) }

func enumerateOpenCLGPUs() ([]uintptr, error) {
	a, err := loadOpenCLWin()
	if err != nil {
		return nil, err
	}

	var platformCount uint32
	rc := clStatus(a.clGetPlatformIDs, 0, 0, ptr(unsafe.Pointer(&platformCount)))
	if rc == clPlatformNotFoundKHR || platformCount == 0 {
		return nil, nil
	}
	if rc != clSuccess {
		return nil, fmt.Errorf("clGetPlatformIDs failed: %d", rc)
	}

	platforms := make([]uintptr, platformCount)
	rc = clStatus(a.clGetPlatformIDs, uintptr(platformCount), ptr(unsafe.Pointer(&platforms[0])), 0)
	if rc != clSuccess {
		return nil, fmt.Errorf("clGetPlatformIDs(list) failed: %d", rc)
	}

	devices := make([]uintptr, 0, windowsMaxGPUDevices)
	for _, platform := range platforms {
		if len(devices) >= windowsMaxGPUDevices {
			break
		}
		var deviceCount uint32
		rc = clStatus(a.clGetDeviceIDs, platform, uintptr(clDeviceTypeGPU), 0, 0, ptr(unsafe.Pointer(&deviceCount)))
		if rc == clDeviceNotFound || deviceCount == 0 {
			continue
		}
		if rc != clSuccess {
			continue
		}

		platformDevices := make([]uintptr, deviceCount)
		rc = clStatus(a.clGetDeviceIDs, platform, uintptr(clDeviceTypeGPU), uintptr(deviceCount), ptr(unsafe.Pointer(&platformDevices[0])), 0)
		if rc != clSuccess {
			continue
		}
		for _, device := range platformDevices {
			if len(devices) == windowsMaxGPUDevices {
				break
			}
			devices = append(devices, device)
		}
	}
	runtime.KeepAlive(platforms)
	return devices, nil
}

func openCLDeviceInfo(index int, device uintptr) (GPUDeviceInfo, error) {
	a, err := loadOpenCLWin()
	if err != nil {
		return GPUDeviceInfo{}, err
	}

	nameBuf := make([]byte, 512)
	rc := clStatus(a.clGetDeviceInfo, device, uintptr(clDeviceName), uintptr(len(nameBuf)), ptr(unsafe.Pointer(&nameBuf[0])), 0)
	name := fmt.Sprintf("OpenCL GPU %d", index)
	if rc == clSuccess {
		if end := bytes.IndexByte(nameBuf, 0); end >= 0 {
			nameBuf = nameBuf[:end]
		}
		if len(nameBuf) != 0 {
			name = string(nameBuf)
		}
	}

	var globalMem uint64
	rc = clStatus(a.clGetDeviceInfo, device, uintptr(clDeviceGlobalMemSize), unsafe.Sizeof(globalMem), ptr(unsafe.Pointer(&globalMem)), 0)
	if rc != clSuccess {
		return GPUDeviceInfo{}, errors.New("cannot query GPU global memory")
	}
	var maxAlloc uint64
	rc = clStatus(a.clGetDeviceInfo, device, uintptr(clDeviceMaxMemAllocSize), unsafe.Sizeof(maxAlloc), ptr(unsafe.Pointer(&maxAlloc)), 0)
	if rc != clSuccess {
		return GPUDeviceInfo{}, errors.New("cannot query GPU max allocation")
	}

	return GPUDeviceInfo{Index: index, Name: name, GlobalMem: globalMem, MaxAlloc: maxAlloc}, nil
}

func ListOpenCLGPUs() ([]GPUDeviceInfo, error) {
	devices, err := enumerateOpenCLGPUs()
	if err != nil {
		return nil, err
	}
	out := make([]GPUDeviceInfo, 0, len(devices))
	for i, device := range devices {
		info, err := openCLDeviceInfo(i, device)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

type OpenCLGPU struct {
	Info     GPUDeviceInfo
	N        uint32
	R        uint32
	Capacity int

	dev   uintptr
	ctx   uintptr
	queue uintptr

	source      []byte
	program     uintptr
	initKernel  uintptr
	loopKernel  uintptr
	finalKernel uintptr

	globalMem uint64
	maxAlloc  uint64
	cancel    atomic.Bool

	passwords uintptr
	pwLens    uintptr
	salt      uintptr
	p         uintptr
	scratch   uintptr
	s         uintptr
	yctx      uintptr
	v         [4]uintptr
	out       uintptr
}

func NewOpenCLGPU(info GPUDeviceInfo) (*OpenCLGPU, error) {
	if yescryptOpenCLSource == "" {
		return nil, errors.New("embedded OpenCL kernel is empty")
	}
	a, err := loadOpenCLWin()
	if err != nil {
		return nil, err
	}
	devices, err := enumerateOpenCLGPUs()
	if err != nil {
		return nil, err
	}
	if info.Index < 0 || info.Index >= len(devices) {
		return nil, fmt.Errorf("OpenCL GPU index %d out of range (found %d)", info.Index, len(devices))
	}

	g := &OpenCLGPU{
		Info:      info,
		dev:       devices[info.Index],
		source:    []byte(yescryptOpenCLSource),
		globalMem: info.GlobalMem,
		maxAlloc:  info.MaxAlloc,
	}
	if g.globalMem == 0 || g.maxAlloc == 0 {
		queried, qerr := openCLDeviceInfo(info.Index, g.dev)
		if qerr != nil {
			return nil, qerr
		}
		g.Info = queried
		g.globalMem = queried.GlobalMem
		g.maxAlloc = queried.MaxAlloc
	}

	var rc int32
	dev := g.dev
	r1, _, _ := a.clCreateContext.Call(0, 1, ptr(unsafe.Pointer(&dev)), 0, 0, ptr(unsafe.Pointer(&rc)))
	g.ctx = r1
	if g.ctx == 0 || rc != clSuccess {
		g.Close()
		return nil, fmt.Errorf("clCreateContext failed: %d", rc)
	}

	r1, _, _ = a.clCreateCommandQueue.Call(g.ctx, g.dev, 0, ptr(unsafe.Pointer(&rc)))
	g.queue = r1
	if g.queue == 0 || rc != clSuccess {
		g.Close()
		return nil, fmt.Errorf("clCreateCommandQueue failed: %d", rc)
	}
	return g, nil
}

func (g *OpenCLGPU) releaseBuffers() {
	if g == nil {
		return
	}
	a, err := loadOpenCLWin()
	if err != nil {
		return
	}
	all := []*uintptr{
		&g.passwords, &g.pwLens, &g.salt, &g.p, &g.scratch, &g.s, &g.yctx,
		&g.v[0], &g.v[1], &g.v[2], &g.v[3], &g.out,
	}
	for _, mem := range all {
		if *mem != 0 {
			_, _, _ = a.clReleaseMemObject.Call(*mem)
			*mem = 0
		}
	}
	g.Capacity = 0
}

func (g *OpenCLGPU) releaseProgram() {
	if g == nil {
		return
	}
	a, err := loadOpenCLWin()
	if err != nil {
		return
	}
	if g.initKernel != 0 {
		_, _, _ = a.clReleaseKernel.Call(g.initKernel)
		g.initKernel = 0
	}
	if g.loopKernel != 0 {
		_, _, _ = a.clReleaseKernel.Call(g.loopKernel)
		g.loopKernel = 0
	}
	if g.finalKernel != 0 {
		_, _, _ = a.clReleaseKernel.Call(g.finalKernel)
		g.finalKernel = 0
	}
	if g.program != 0 {
		_, _, _ = a.clReleaseProgram.Call(g.program)
		g.program = 0
	}
	g.N = 0
	g.R = 0
}

func (g *OpenCLGPU) Close() {
	if g == nil {
		return
	}
	a, _ := loadOpenCLWin()
	g.releaseBuffers()
	g.releaseProgram()
	if a != nil {
		if g.queue != 0 {
			_, _, _ = a.clReleaseCommandQueue.Call(g.queue)
			g.queue = 0
		}
		if g.ctx != 0 {
			_, _, _ = a.clReleaseContext.Call(g.ctx)
			g.ctx = 0
		}
	}
	g.source = nil
}

func (g *OpenCLGPU) Cancel() {
	if g != nil {
		g.cancel.Store(true)
	}
}

func (g *OpenCLGPU) ResetCancel() {
	if g != nil {
		g.cancel.Store(false)
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

func nulTerminated(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func (g *OpenCLGPU) buildSpecializedProgram(N, r uint32) error {
	if g.program != 0 && g.N == N && g.R == r {
		return nil
	}
	g.releaseProgram()

	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	if len(g.source) == 0 {
		return errors.New("empty OpenCL source")
	}

	sourcePtr := ptr(unsafe.Pointer(&g.source[0]))
	sources := [1]uintptr{sourcePtr}
	lengths := [1]uintptr{uintptr(len(g.source))}
	var rc int32
	r1, _, _ := a.clCreateProgramWithSource.Call(
		g.ctx,
		1,
		ptr(unsafe.Pointer(&sources[0])),
		ptr(unsafe.Pointer(&lengths[0])),
		ptr(unsafe.Pointer(&rc)),
	)
	g.program = r1
	if g.program == 0 || rc != clSuccess {
		g.releaseProgram()
		return fmt.Errorf("clCreateProgramWithSource failed: %d", rc)
	}
	runtime.KeepAlive(g.source)

	optionsText := fmt.Sprintf("-cl-std=CL1.2 -DYC_N=%d -DYC_R=%d", N, r)
	options := nulTerminated(optionsText)
	dev := g.dev
	rc = clStatus(a.clBuildProgram,
		g.program,
		1,
		ptr(unsafe.Pointer(&dev)),
		ptr(unsafe.Pointer(&options[0])),
		0,
		0,
	)
	if rc != clSuccess {
		var logSize uintptr
		_ = clStatus(a.clGetProgramBuildInfo, g.program, g.dev, uintptr(clProgramBuildLog), 0, 0, ptr(unsafe.Pointer(&logSize)))
		logText := "no build log"
		if logSize > 0 {
			logBuf := make([]byte, int(logSize)+1)
			if clStatus(a.clGetProgramBuildInfo, g.program, g.dev, uintptr(clProgramBuildLog), logSize, ptr(unsafe.Pointer(&logBuf[0])), 0) == clSuccess {
				if end := bytes.IndexByte(logBuf, 0); end >= 0 {
					logBuf = logBuf[:end]
				}
				if len(logBuf) != 0 {
					logText = string(logBuf)
				}
			}
		}
		g.releaseProgram()
		return fmt.Errorf("OpenCL kernel build failed (%d) [%s]: %s", rc, optionsText, logText)
	}

	createKernel := func(name string) (uintptr, error) {
		kernelName := nulTerminated(name)
		var kernelRC int32
		kernel, _, _ := a.clCreateKernel.Call(g.program, ptr(unsafe.Pointer(&kernelName[0])), ptr(unsafe.Pointer(&kernelRC)))
		if kernel == 0 || kernelRC != clSuccess {
			return 0, fmt.Errorf("clCreateKernel(%s) failed: %d", name, kernelRC)
		}
		return kernel, nil
	}
	if g.initKernel, err = createKernel("yescrypt_init"); err != nil {
		g.releaseProgram()
		return err
	}
	if g.loopKernel, err = createKernel("yescrypt_loop"); err != nil {
		g.releaseProgram()
		return err
	}
	if g.finalKernel, err = createKernel("yescrypt_final"); err != nil {
		g.releaseProgram()
		return err
	}

	g.N = N
	g.R = r
	return nil
}

func (g *OpenCLGPU) makeBuffer(flags uint64, size uint64, what string) (uintptr, error) {
	a, err := loadOpenCLWin()
	if err != nil {
		return 0, err
	}
	if size == 0 {
		size = 8
	}
	var rc int32
	mem, _, _ := a.clCreateBuffer.Call(g.ctx, uintptr(flags), uintptr(size), 0, ptr(unsafe.Pointer(&rc)))
	if mem == 0 || rc != clSuccess {
		return 0, fmt.Errorf("clCreateBuffer(%s, %.2f MiB) failed: %d", what, float64(size)/(1024.0*1024.0), rc)
	}
	return mem, nil
}

func (g *OpenCLGPU) Configure(N, r uint32, batchHint int) (int, error) {
	if g == nil || g.ctx == 0 {
		return 0, errors.New("GPU context is closed")
	}
	if batchHint < 0 {
		batchHint = 0
	}
	if N == 0 || r == 0 || r > windowsMaxR || N&(N-1) != 0 {
		return 0, fmt.Errorf("invalid yescrypt GPU parameters N=%d r=%d", N, r)
	}

	geometryChanged := g.N != N || g.R != r || g.program == 0
	if !geometryChanged && g.Capacity != 0 && (batchHint == 0 || batchHint == g.Capacity) {
		return g.Capacity, nil
	}

	g.releaseBuffers()
	if err := g.buildSpecializedProgram(N, r); err != nil {
		return 0, err
	}

	stateBytes := uint64(128) * uint64(r)
	vbytes := stateBytes * uint64(N)
	scratchBytes := stateBytes
	if scratchBytes < 256 {
		scratchBytes = 256
	}
	const ctxBytes = uint64(48)
	workspace := uint64(gpuMaxPasswordLen) + 4 + 64 + stateBytes + scratchBytes + windowsSWords*8 + ctxBytes + 32

	reserve := g.globalMem / 10
	if reserve < 512*windowsOneMiB {
		reserve = 512 * windowsOneMiB
	}
	if reserve >= g.globalMem {
		reserve = g.globalMem / 5
	}
	usable := g.globalMem - reserve
	capMem := usable / (vbytes + workspace)

	allocLimit := g.maxAlloc * 95 / 100
	slotsPerSegment := uint64(0)
	if vbytes != 0 {
		slotsPerSegment = allocLimit / vbytes
	}
	capAlloc := slotsPerSegment * 4
	cap := capMem
	if cap > capAlloc {
		cap = capAlloc
	}
	if cap > 4096 {
		cap = 4096
	}
	if batchHint > 0 {
		if cap > uint64(batchHint) {
			cap = uint64(batchHint)
		}
	} else {
		cap = cap * 95 / 100
		if cap >= 32 {
			cap = cap / 32 * 32
		}
	}
	if cap == 0 {
		return 0, fmt.Errorf("GPU cannot allocate one yescrypt V region: need %.2f MiB/candidate, max allocation %.2f MiB", float64(vbytes)/float64(windowsOneMiB), float64(g.maxAlloc)/float64(windowsOneMiB))
	}
	if cap >= 4 {
		cap = cap / 4 * 4
	}
	if cap == 0 {
		cap = 1
	}
	g.Capacity = int(cap)

	var err error
	if g.passwords, err = g.makeBuffer(clMemReadOnly, cap*uint64(gpuMaxPasswordLen), "passwords"); err != nil {
		goto fail
	}
	if g.pwLens, err = g.makeBuffer(clMemReadOnly, cap*4, "pw_lens"); err != nil {
		goto fail
	}
	if g.salt, err = g.makeBuffer(clMemReadOnly, 64, "salt"); err != nil {
		goto fail
	}
	if g.p, err = g.makeBuffer(clMemReadWrite, cap*stateBytes, "P"); err != nil {
		goto fail
	}
	if g.scratch, err = g.makeBuffer(clMemReadWrite, cap*scratchBytes, "scratch"); err != nil {
		goto fail
	}
	if g.s, err = g.makeBuffer(clMemReadWrite, cap*windowsSWords*8, "S"); err != nil {
		goto fail
	}
	if g.yctx, err = g.makeBuffer(clMemReadWrite, cap*ctxBytes, "context"); err != nil {
		goto fail
	}
	for seg := 0; seg < 4; seg++ {
		segCount := (cap + uint64(3-seg)) / 4
		if g.v[seg], err = g.makeBuffer(clMemReadWrite, segCount*vbytes, fmt.Sprintf("V%d", seg)); err != nil {
			goto fail
		}
	}
	if g.out, err = g.makeBuffer(clMemWriteOnly, cap*32, "output"); err != nil {
		goto fail
	}
	return g.Capacity, nil

fail:
	g.releaseBuffers()
	return 0, err
}

func (g *OpenCLGPU) setKernelMem(kernel uintptr, arg *uint32, mem uintptr, label string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	value := mem
	rc := clStatus(a.clSetKernelArg, kernel, uintptr(*arg), unsafe.Sizeof(value), ptr(unsafe.Pointer(&value)))
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", label, rc)
	}
	(*arg)++
	return nil
}

func (g *OpenCLGPU) setKernelU32(kernel uintptr, arg *uint32, value uint32, label string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	v := value
	rc := clStatus(a.clSetKernelArg, kernel, uintptr(*arg), unsafe.Sizeof(v), ptr(unsafe.Pointer(&v)))
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", label, rc)
	}
	(*arg)++
	return nil
}

func (g *OpenCLGPU) enqueueWrite(mem uintptr, size uintptr, data unsafe.Pointer, what string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	rc := clStatus(a.clEnqueueWriteBuffer, g.queue, mem, uintptr(clFalse), 0, size, ptr(data), 0, 0, 0)
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", what, rc)
	}
	return nil
}

func (g *OpenCLGPU) enqueueKernel(kernel uintptr, global, local uintptr, what string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	globalSize := global
	var localPtr uintptr
	var localSize uintptr
	if local != 0 {
		localSize = local
		localPtr = ptr(unsafe.Pointer(&localSize))
	}
	rc := clStatus(a.clEnqueueNDRangeKernel, g.queue, kernel, 1, 0, ptr(unsafe.Pointer(&globalSize)), localPtr, 0, 0, 0)
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", what, rc)
	}
	return nil
}

func (g *OpenCLGPU) finish(what string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	rc := clStatus(a.clFinish, g.queue)
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", what, rc)
	}
	return nil
}

func (g *OpenCLGPU) enqueueRead(mem uintptr, size uintptr, data unsafe.Pointer, what string) error {
	a, err := loadOpenCLWin()
	if err != nil {
		return err
	}
	rc := clStatus(a.clEnqueueReadBuffer, g.queue, mem, uintptr(clTrue), 0, size, ptr(data), 0, 0, 0)
	if rc != clSuccess {
		return fmt.Errorf("%s failed: %d", what, rc)
	}
	return nil
}

// HashBatch mirrors the tuned Linux host sequence. Windows uses the same
// embedded kernel and workgroup geometry, but calls OpenCL.dll directly from Go.
func (g *OpenCLGPU) HashBatch(passwords [][]byte, salt []byte) ([][32]byte, error) {
	if g == nil || g.ctx == 0 || g.Capacity == 0 {
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
	if g.cancel.Load() {
		return nil, errGPUCancelled
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

	var hostPin runtime.Pinner
	hostPin.Pin(&packed[0])
	hostPin.Pin(&lens[0])
	hostPin.Pin(&rawOut[0])
	defer hostPin.Unpin()

	if err := g.hashPacked(packed, lens, salt, rawOut); err != nil {
		return nil, err
	}
	runtime.KeepAlive(packed)
	runtime.KeepAlive(lens)
	runtime.KeepAlive(salt)
	runtime.KeepAlive(rawOut)

	out := make([][32]byte, len(passwords))
	for i := range out {
		copy(out[i][:], rawOut[i*32:(i+1)*32])
	}
	return out, nil
}

func (g *OpenCLGPU) hashPacked(packed []byte, lens []uint32, salt []byte, rawOut []byte) error {
	count := uint32(len(lens))
	if count == 0 || int(count) > g.Capacity || g.program == 0 {
		return fmt.Errorf("bad GPU batch count %d (capacity %d)", count, g.Capacity)
	}
	if g.cancel.Load() {
		return errGPUCancelled
	}

	if err := g.enqueueWrite(g.passwords, uintptr(count)*gpuMaxPasswordLen, unsafe.Pointer(&packed[0]), "write passwords"); err != nil {
		return err
	}
	if err := g.enqueueWrite(g.pwLens, uintptr(count)*4, unsafe.Pointer(&lens[0]), "write password lengths"); err != nil {
		return err
	}
	var saltBuf [64]byte
	copy(saltBuf[:], salt)
	var saltPin runtime.Pinner
	saltPin.Pin(&saltBuf[0])
	defer saltPin.Unpin()
	if err := g.enqueueWrite(g.salt, 64, unsafe.Pointer(&saltBuf[0]), "write salt"); err != nil {
		return err
	}

	var a uint32
	for _, item := range []struct {
		mem   uintptr
		label string
	}{
		{g.passwords, "set init passwords"},
		{g.pwLens, "set init lengths"},
		{g.salt, "set init salt"},
	} {
		if err := g.setKernelMem(g.initKernel, &a, item.mem, item.label); err != nil {
			return err
		}
	}
	if err := g.setKernelU32(g.initKernel, &a, uint32(len(salt)), "set init salt_len"); err != nil {
		return err
	}
	if err := g.setKernelU32(g.initKernel, &a, count, "set init count"); err != nil {
		return err
	}
	for _, item := range []struct {
		mem   uintptr
		label string
	}{
		{g.p, "set init P"},
		{g.scratch, "set init scratch"},
		{g.s, "set init S"},
		{g.yctx, "set init context"},
		{g.v[0], "set init V0"},
		{g.v[1], "set init V1"},
		{g.v[2], "set init V2"},
		{g.v[3], "set init V3"},
	} {
		if err := g.setKernelMem(g.initKernel, &a, item.mem, item.label); err != nil {
			return err
		}
	}
	if err := g.enqueueKernel(g.initKernel, uintptr(count), 0, "launch yescrypt init"); err != nil {
		return err
	}

	nloop := (((uint64(g.N) + 2) / 3) + 1) &^ uint64(1)
	remaining := uint64(g.N) + nloop
	const localLoop = uintptr(32)
	globalLoop := uintptr(count) * localLoop
	for remaining != 0 {
		if g.cancel.Load() {
			_ = g.finish("cancel wait")
			return errGPUCancelled
		}
		chunk := uint32(remaining)
		if remaining > 2048 {
			chunk = 2048
		}
		a = 0
		if err := g.setKernelU32(g.loopKernel, &a, count, "set loop count"); err != nil {
			return err
		}
		if err := g.setKernelU32(g.loopKernel, &a, chunk, "set loop chunk"); err != nil {
			return err
		}
		for _, item := range []struct {
			mem   uintptr
			label string
		}{
			{g.p, "set loop P"},
			{g.s, "set loop S"},
			{g.yctx, "set loop context"},
			{g.v[0], "set loop V0"},
			{g.v[1], "set loop V1"},
			{g.v[2], "set loop V2"},
			{g.v[3], "set loop V3"},
		} {
			if err := g.setKernelMem(g.loopKernel, &a, item.mem, item.label); err != nil {
				return err
			}
		}
		if err := g.enqueueKernel(g.loopKernel, globalLoop, localLoop, "launch yescrypt cooperative loop"); err != nil {
			return err
		}
		if err := g.finish("wait for yescrypt cooperative loop"); err != nil {
			return err
		}
		if g.cancel.Load() {
			return errGPUCancelled
		}
		remaining -= uint64(chunk)
	}

	if g.cancel.Load() {
		return errGPUCancelled
	}
	a = 0
	if err := g.setKernelU32(g.finalKernel, &a, count, "set final count"); err != nil {
		return err
	}
	for _, item := range []struct {
		mem   uintptr
		label string
	}{
		{g.p, "set final P"},
		{g.scratch, "set final scratch"},
		{g.yctx, "set final context"},
		{g.out, "set final output"},
	} {
		if err := g.setKernelMem(g.finalKernel, &a, item.mem, item.label); err != nil {
			return err
		}
	}
	if err := g.enqueueKernel(g.finalKernel, uintptr(count), 0, "launch yescrypt final"); err != nil {
		return err
	}
	if err := g.enqueueRead(g.out, uintptr(count)*32, unsafe.Pointer(&rawOut[0]), "read yescrypt output"); err != nil {
		return err
	}
	if err := g.finish("clFinish"); err != nil {
		return err
	}
	return nil
}
