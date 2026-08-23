package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type RuntimeOptions struct {
	UseGPU      bool
	GPUList     string // "all" or comma-separated OpenCL GPU indexes
	GPUBatch    int    // 0 = automatic
	PreparedGPU *gpuRuntime
}

type hashGroup struct {
	N       uint32
	R       uint32
	Salt    []byte
	Indices []int
}

func makeHashGroups(hashes []YescryptHash) []hashGroup {
	type key struct {
		N, R uint32
		Salt string
	}
	m := make(map[key]int)
	var groups []hashGroup
	for i := range hashes {
		if !hashes[i].GPUOK {
			continue
		}
		k := key{hashes[i].N, hashes[i].R, string(hashes[i].Salt)}
		if pos, ok := m[k]; ok {
			groups[pos].Indices = append(groups[pos].Indices, i)
			continue
		}
		m[k] = len(groups)
		groups = append(groups, hashGroup{N: k.N, R: k.R, Salt: append([]byte(nil), hashes[i].Salt...), Indices: []int{i}})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].N != groups[j].N {
			return groups[i].N < groups[j].N
		}
		if groups[i].R != groups[j].R {
			return groups[i].R < groups[j].R
		}
		return bytes.Compare(groups[i].Salt, groups[j].Salt) < 0
	})
	return groups
}

func groupHasUncracked(hashes []YescryptHash, g *hashGroup) bool {
	for _, idx := range g.Indices {
		if atomic.LoadInt32(&hashes[idx].Cracked) == 0 {
			return true
		}
	}
	return false
}

func parseGPUSelection(spec string, devices []GPUDeviceInfo) ([]GPUDeviceInfo, error) {
	if len(devices) == 0 {
		return nil, nil
	}
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "all" {
		return append([]GPUDeviceInfo(nil), devices...), nil
	}
	seen := make(map[int]bool)
	var out []GPUDeviceInfo
	for _, field := range strings.Split(spec, ",") {
		i, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || i < 0 || i >= len(devices) {
			return nil, fmt.Errorf("invalid -gpu value %q; available indexes are 0..%d", field, len(devices)-1)
		}
		if !seen[i] {
			seen[i] = true
			out = append(out, devices[i])
		}
	}
	return out, nil
}

func tuneAutoGPUCapacity(cap uint64) uint64 {
	if cap == 0 {
		return 0
	}

	tuned := cap * 95 / 100
	if tuned >= 32 {
		tuned = tuned / 32 * 32
	}
	if tuned == 0 {
		tuned = 1
	}
	return tuned
}

func estimateGPUCapacity(info GPUDeviceInfo, N, r uint32, batchHint int) int {
	if N == 0 || r == 0 {
		return 0
	}
	vbytes := uint64(128) * uint64(N) * uint64(r)
	stateBytes := uint64(128) * uint64(r)
	scratchBytes := stateBytes
	if scratchBytes < 256 {
		scratchBytes = 256
	}
	workspace := uint64(gpuMaxPasswordLen+4+64+32+48+1536*8) + stateBytes + scratchBytes
	reserve := info.GlobalMem / 10
	const mib = uint64(1024 * 1024)
	if reserve < 512*mib {
		reserve = 512 * mib
	}
	if reserve >= info.GlobalMem {
		reserve = info.GlobalMem / 5
	}
	usable := info.GlobalMem - reserve
	capMem := usable / (vbytes + workspace)
	allocLimit := info.MaxAlloc * 95 / 100
	capAlloc := (allocLimit / vbytes) * 4
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
		cap = tuneAutoGPUCapacity(cap)
	}

	if cap >= 4 {
		cap = cap / 4 * 4
	}
	return int(cap)
}

func minGPUCapacity(info GPUDeviceInfo, groups []hashGroup, batchHint int) int {
	minCap := 0
	seen := make(map[[2]uint32]bool)
	for i := range groups {
		cfg := [2]uint32{groups[i].N, groups[i].R}
		if seen[cfg] {
			continue
		}
		seen[cfg] = true
		cap := estimateGPUCapacity(info, cfg[0], cfg[1], batchHint)
		if cap <= 0 {
			return 0
		}
		if minCap == 0 || cap < minCap {
			minCap = cap
		}
	}
	return minCap
}

func startProcWithOptions(wordlistFileFlag string, outputPath string, numGoroutines int, hashes []YescryptHash, crackedCount *int32, linesProcessed *uint64, totalHashesGenerated *uint64, stopChan chan struct{}, opts RuntimeOptions) error {
	file, err := openWordlist(wordlistFileFlag)
	if err != nil {
		log.Fatalf("Error opening wordlist: %v", err)
	}
	if file != os.Stdin {
		defer file.Close()
	}
	writer, outputFile, err := openOutput(outputPath)
	if err != nil {
		log.Fatalf("Error opening output: %v", err)
	}
	if outputFile != nil {
		defer outputFile.Close()
	}
	defer writer.Flush()

	var writerMu sync.Mutex
	if opts.UseGPU {
		if opts.PreparedGPU != nil {
			usedGPU, gpuErr := runPreparedGPUProcessor(file, opts.PreparedGPU, &writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
			if gpuErr != nil {
				return gpuErr
			}
			if usedGPU {
				log.Println("Finished")
				return nil
			}
			log.Printf("No usable OpenCL yescrypt groups; falling back to CPU")
		} else {
			devices, derr := ListOpenCLGPUs()
			if derr != nil {
				log.Printf("OpenCL unavailable (%v); falling back to CPU", derr)
			} else {
				selected, serr := parseGPUSelection(opts.GPUList, devices)
				if serr != nil {
					log.Printf("%v; falling back to CPU", serr)
				} else if len(selected) != 0 {
					groups := makeHashGroups(hashes)
					if len(groups) != 0 {
						usedGPU, gpuErr := runGPUProcessor(file, selected, opts.GPUBatch, groups, hashes, &writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
						if gpuErr != nil {
							return gpuErr
						}
						if usedGPU {
							log.Println("Finished")
							return nil
						}
					}
					log.Printf("No usable OpenCL yescrypt groups; falling back to CPU")
				} else {
					log.Printf("No OpenCL GPU devices found; falling back to CPU")
				}
			}
		}
	}

	runCPUProcessor(file, numGoroutines, hashes, &writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
	log.Println("Finished")
	return nil
}

func openWordlist(path string) (*os.File, error) {
	if path == "" {
		return os.Stdin, nil
	}
	return os.Open(path)
}

func openOutput(path string) (*bufio.Writer, *os.File, error) {
	if path == "" {
		return bufio.NewWriter(os.Stdout), nil, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, err
	}
	return bufio.NewWriter(f), f, nil
}

func runCPUProcessor(file *os.File, numGoroutines int, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan chan struct{}) {
	var wg sync.WaitGroup
	linesCh := make(chan []byte, 1000)
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range linesCh {
				select {
				case <-stopChan:
					return
				default:
				}
				processPassword(password, hashes, writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
readLoop:
	for scanner.Scan() {
		select {
		case <-stopChan:
			break readLoop
		default:
		}
		decodedPassword, _, _ := checkForHexBytes(scanner.Bytes())
		password := append([]byte(nil), decodedPassword...)
		select {
		case linesCh <- password:
		case <-stopChan:
			break readLoop
		}
	}
	close(linesCh)
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading wordlist: %v", err)
	}
	wg.Wait()
}

type gpuTask struct{ Passwords [][]byte }

type gpuWorker struct {
	gpu      *OpenCLGPU
	info     GPUDeviceInfo
	groups   []hashGroup
	hashes   []YescryptHash
	batchCap int
	failed   bool
}

type gpuRuntime struct {
	workers []*gpuWorker
	feedCap int
}

func (rt *gpuRuntime) Close() {
	if rt == nil {
		return
	}
	for _, w := range rt.workers {
		if w != nil && w.gpu != nil {
			w.gpu.Close()
		}
	}
	rt.workers = nil
}

func prepareGPUProcessor(devices []GPUDeviceInfo, batchHint int, groups []hashGroup, hashes []YescryptHash, stopChan <-chan struct{}) *gpuRuntime {
	if len(devices) == 0 || len(groups) == 0 {
		return nil
	}

	type prepResult struct {
		worker *gpuWorker
	}

	results := make(chan prepResult, len(devices))
	var prepWG sync.WaitGroup
	for _, info := range devices {
		info := info
		prepWG.Add(1)
		go func() {
			defer prepWG.Done()

			select {
			case <-stopChan:
				return
			default:
			}

			cap := minGPUCapacity(info, groups, batchHint)
			if cap <= 0 {
				log.Printf("OpenCL GPU %d (%s) does not have enough allocatable VRAM for these yescrypt parameters", info.Index, info.Name)
				return
			}

			gpu, err := NewOpenCLGPU(info)
			if err != nil {
				log.Printf("OpenCL GPU %d (%s) initialization failed: %v", info.Index, info.Name, err)
				return
			}

			cancelDone := make(chan struct{})
			cancelExit := make(chan struct{})
			go func() {
				defer close(cancelExit)
				select {
				case <-stopChan:
					gpu.Cancel()
				case <-cancelDone:
				}
			}()
			finishCancelWatch := func() {
				close(cancelDone)
				<-cancelExit
			}

			if err := gpu.SelfTest(); err != nil {
				finishCancelWatch()
				select {
				case <-stopChan:
					gpu.Close()
					return
				default:
				}
				log.Printf("OpenCL GPU %d (%s) self-test failed: %v", info.Index, info.Name, err)
				gpu.Close()
				return
			}
			gpu.ResetCancel()

			w := &gpuWorker{gpu: gpu, info: info, groups: groups, hashes: hashes, batchCap: cap}

			actualCap, err := configureGPUWithBackoff(w, groups[0].N, groups[0].R)
			finishCancelWatch()
			if err != nil {
				select {
				case <-stopChan:
					gpu.Close()
					return
				default:
				}
				log.Printf("OpenCL GPU %d (%s) tuning failed: %v", info.Index, info.Name, err)
				gpu.Close()
				return
			}

			select {
			case <-stopChan:
				gpu.Close()
				return
			default:
			}

			log.Printf("OpenCL GPU %d: %s, %.1f GiB VRAM, batch cap %d, self-test passed",
				info.Index, info.Name, float64(info.GlobalMem)/(1<<30), actualCap)
			results <- prepResult{worker: w}
		}()
	}

	prepWG.Wait()
	close(results)

	var workers []*gpuWorker
	for result := range results {
		if result.worker != nil {
			workers = append(workers, result.worker)
		}
	}
	if len(workers) == 0 {
		return nil
	}

	sort.Slice(workers, func(i, j int) bool { return workers[i].info.Index < workers[j].info.Index })
	feedCap := workers[0].batchCap
	for _, w := range workers[1:] {
		if w.batchCap < feedCap {
			feedCap = w.batchCap
		}
	}
	if feedCap < 1 {
		for _, w := range workers {
			w.gpu.Close()
		}
		return nil
	}

	return &gpuRuntime{workers: workers, feedCap: feedCap}
}

func runGPUProcessor(file *os.File, devices []GPUDeviceInfo, batchHint int, groups []hashGroup, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan chan struct{}) (bool, error) {
	rt := prepareGPUProcessor(devices, batchHint, groups, hashes, stopChan)
	if rt == nil {
		return false, nil
	}
	return runPreparedGPUProcessor(file, rt, writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan)
}

func runPreparedGPUProcessor(file *os.File, rt *gpuRuntime, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan chan struct{}) (bool, error) {
	if rt == nil || len(rt.workers) == 0 || rt.feedCap < 1 {
		return false, nil
	}

	workers := rt.workers
	feedCap := rt.feedCap
	defer rt.Close()

	cancelWatchDone := make(chan struct{})
	cancelWatchExit := make(chan struct{})
	go func() {
		defer close(cancelWatchExit)
		select {
		case <-stopChan:
			for _, w := range workers {
				w.gpu.Cancel()
			}
		case <-cancelWatchDone:
		}
	}()
	defer func() {
		close(cancelWatchDone)
		<-cancelWatchExit
	}()

	tasks := make(chan gpuTask, len(workers)*2)
	fatalSignal := make(chan struct{})
	var fatalOnce sync.Once
	var fatalErr error
	reportFatal := func(err error) {
		if err == nil {
			return
		}
		fatalOnce.Do(func() {
			fatalErr = err
			close(fatalSignal)
			for _, worker := range workers {
				worker.gpu.Cancel()
			}
		})
	}

	var wg sync.WaitGroup
	for _, w := range workers {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				select {
				case <-stopChan:
					return
				case <-fatalSignal:
					return
				default:
				}
				if err := processGPUBatch(w, task.Passwords, writerMu, writer, crackedCount, linesProcessed, totalHashesGenerated, stopChan); err != nil {
					reportFatal(err)
					return
				}
			}
		}()
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	batch := make([][]byte, 0, feedCap)
	sendBatch := func() bool {
		if len(batch) == 0 {
			return true
		}
		owned := batch
		batch = make([][]byte, 0, feedCap)
		select {
		case tasks <- gpuTask{Passwords: owned}:
			return true
		case <-stopChan:
			return false
		case <-fatalSignal:
			return false
		}
	}

readLoop:
	for scanner.Scan() {
		select {
		case <-stopChan:
			break readLoop
		case <-fatalSignal:
			break readLoop
		default:
		}
		decoded, _, _ := checkForHexBytes(scanner.Bytes())
		pw := append([]byte(nil), decoded...)
		batch = append(batch, pw)
		if len(batch) == feedCap {
			if !sendBatch() {
				break readLoop
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading wordlist: %v", err)
	}
	select {
	case <-fatalSignal:
		// do not queue a partial trailing batch after a GPU runtime failure
	default:
		if len(batch) != 0 {
			_ = sendBatch()
		}
	}
	close(tasks)
	wg.Wait()
	if fatalErr != nil {
		return true, fatalErr
	}
	return true, nil
}

func configureGPUWithBackoff(w *gpuWorker, N, r uint32) (int, error) {
	hint := w.batchCap
	if hint < 1 {
		hint = 1
	}
	var lastErr error
	for hint >= 1 {
		cap, err := w.gpu.Configure(N, r, hint)
		if err == nil {
			w.batchCap = cap
			return cap, nil
		}
		lastErr = err
		if hint == 1 {
			break
		}
		hint /= 2
		if hint < 1 {
			hint = 1
		}
	}
	return 0, lastErr
}

func processGPUBatch(w *gpuWorker, passwords [][]byte, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan chan struct{}) error {
	select {
	case <-stopChan:
		return nil
	default:
	}

	gpuPW := make([][]byte, 0, len(passwords))
	for _, pw := range passwords {
		select {
		case <-stopChan:
			return nil
		default:
		}
		if len(pw) <= gpuMaxPasswordLen && !w.failed {
			gpuPW = append(gpuPW, pw)
		} else {
			processPasswordNoLineCount(pw, w.hashes, writerMu, writer, crackedCount, totalHashesGenerated, stopChan)
		}
	}
	if len(gpuPW) == 0 {
		atomic.AddUint64(linesProcessed, uint64(len(passwords)))
		return nil
	}

	handled := make([]bool, len(w.hashes))
	for gi := range w.groups {
		g := &w.groups[gi]
		if !groupHasUncracked(w.hashes, g) {
			for _, idx := range g.Indices {
				handled[idx] = true
			}
			continue
		}
		for _, idx := range g.Indices {
			handled[idx] = true
		}
		cap, err := configureGPUWithBackoff(w, g.N, g.R)
		if err != nil {
			w.failed = true
			return fmt.Errorf("OpenCL GPU %d configure failed: %w", w.info.Index, err)
		}
		for off := 0; off < len(gpuPW); off += cap {
			end := off + cap
			if end > len(gpuPW) {
				end = len(gpuPW)
			}
			digests, err := w.gpu.HashBatch(gpuPW[off:end], g.Salt)
			if err != nil {
				if errors.Is(err, errGPUCancelled) {
					return nil
				}
				w.failed = true
				return fmt.Errorf("OpenCL GPU %d execution failed: %w", w.info.Index, err)
			}
			atomic.AddUint64(totalHashesGenerated, uint64(len(digests)))
			for j := range digests {
				pw := gpuPW[off+j]
				applyGPUResult(pw, digests[j], g, w.hashes, writerMu, writer, crackedCount, stopChan)
			}
			select {
			case <-stopChan:
				return nil
			default:
			}
		}
	}

	for idx := range w.hashes {
		if handled[idx] || atomic.LoadInt32(&w.hashes[idx].Cracked) != 0 {
			continue
		}
		for _, pw := range gpuPW {
			select {
			case <-stopChan:
				return nil
			default:
			}
			atomic.AddUint64(totalHashesGenerated, 1)
			if crackParsedHashCPU(pw, &w.hashes[idx]) {
				markCracked(idx, pw, w.hashes, writerMu, writer, crackedCount, stopChan)
			}
		}
	}

	atomic.AddUint64(linesProcessed, uint64(len(passwords)))
	return nil
}

func applyGPUResult(password []byte, digest [32]byte, g *hashGroup, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, stopChan chan struct{}) {
	for _, idx := range g.Indices {
		if atomic.LoadInt32(&hashes[idx].Cracked) != 0 {
			continue
		}
		matched := false
		switch hashes[idx].Kind {
		case HashYescrypt:
			matched = subtle.ConstantTimeCompare(digest[:], hashes[idx].Expected[:]) == 1
		case HashGostYescrypt:
			got, err := gostFinalize(password, hashes[idx].Setting, digest[:])
			if err == nil {
				matched = constantTimeDigestEqual(got, hashes[idx].Expected[:])
			}
		}
		if matched {
			markCracked(idx, password, hashes, writerMu, writer, crackedCount, stopChan)
		}
	}
}

func markCracked(idx int, password []byte, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, stopChan chan struct{}) {
	if !atomic.CompareAndSwapInt32(&hashes[idx].Cracked, 0, 1) {
		return
	}
	output := fmt.Sprintf("%s:%s\n", hashes[idx].Hash, string(password))
	writerMu.Lock()
	atomic.AddInt32(crackedCount, 1)
	if writer != nil {
		_, _ = writer.WriteString(output)
		_ = writer.Flush()
	}
	writerMu.Unlock()
	if isAllHashesCracked(hashes) {
		closeStopChannel(stopChan)
	}
}

func processPassword(password []byte, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, linesProcessed, totalHashesGenerated *uint64, stopChan chan struct{}) {
	atomic.AddUint64(linesProcessed, 1)
	processPasswordNoLineCount(password, hashes, writerMu, writer, crackedCount, totalHashesGenerated, stopChan)
}

func processPasswordNoLineCount(password []byte, hashes []YescryptHash, writerMu *sync.Mutex, writer *bufio.Writer, crackedCount *int32, totalHashesGenerated *uint64, stopChan chan struct{}) {
	for i := range hashes {
		if atomic.LoadInt32(&hashes[i].Cracked) != 0 {
			continue
		}
		atomic.AddUint64(totalHashesGenerated, 1)
		if crackParsedHashCPU(password, &hashes[i]) {
			markCracked(i, password, hashes, writerMu, writer, crackedCount, stopChan)
			select {
			case <-stopChan:
				return
			default:
			}
		}
	}
}
