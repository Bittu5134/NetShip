package netship

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

const (
	hashQueueDepth = 512

	// Far above any real executable on a workstation, far below the point where
	// reading the file becomes a stall. Bigger "executables" are data files or a
	// deleted image path.
	hashMaxSize = 64 << 20

	hashCacheCap = 4096

	hashChunkSize = 1 << 20
)

// Hasher is a cache with one worker attached, same shape as Enricher. Callers
// read Get and never wait.
type Hasher struct {
	mu       sync.RWMutex
	cache    map[string]string
	failed   map[string]bool
	inflight map[string]struct{}

	queue chan string
	once  sync.Once
}

func NewHasher() *Hasher {
	return &Hasher{
		cache:    make(map[string]string),
		failed:   make(map[string]bool),
		inflight: make(map[string]struct{}),
		queue:    make(chan string, hashQueueDepth),
	}
}

func (h *Hasher) Start(ctx context.Context) {
	if h == nil {
		return
	}
	h.once.Do(func() { go h.worker(ctx) })
}

// Safe to call every tick for every socket: the cache, the negative cache and
// the in-flight set filter repeats, and a full queue drops rather than blocks.
func (h *Hasher) Request(exe string) {
	if h == nil || exe == "" {
		return
	}

	// Stat here rather than in the worker. Sockets, directories and paths with
	// " (deleted)" in them are not work in the first place.
	st, err := os.Stat(exe)
	if err != nil || !st.Mode().IsRegular() || st.Size() > hashMaxSize {
		return
	}

	h.mu.Lock()
	if _, ok := h.cache[exe]; ok {
		h.mu.Unlock()
		return
	}
	if h.failed[exe] {
		h.mu.Unlock()
		return
	}
	if _, busy := h.inflight[exe]; busy {
		h.mu.Unlock()
		return
	}
	h.inflight[exe] = struct{}{}
	h.mu.Unlock()

	select {
	case h.queue <- exe:
	default:
		// Clear the mark too, or this path is never retried once the queue
		// drains.
		h.mu.Lock()
		delete(h.inflight, exe)
		h.mu.Unlock()
	}
}

func (h *Hasher) Get(exe string) (string, bool) {
	if h == nil || exe == "" {
		return "", false
	}
	h.mu.RLock()
	sum, ok := h.cache[exe]
	h.mu.RUnlock()
	return sum, ok
}

func (h *Hasher) worker(ctx context.Context) {
	buf := make([]byte, hashChunkSize)
	for {
		select {
		case <-ctx.Done():
			return
		case exe := <-h.queue:
			sum, ok := hashFile(exe, buf)
			h.store(exe, sum, ok)
		}
	}
}

// The only thing here that touches disk. A partial hash would be worse than no
// hash, so anything that cannot be read to the end reports false.
func hashFile(exe string, buf []byte) (string, bool) {
	f, err := os.Open(exe)
	if err != nil {
		return "", false
	}
	defer f.Close()

	// Checked again after opening: the file can be replaced or grow between the
	// stat in Request and this read.
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > hashMaxSize {
		return "", false
	}

	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// The in-flight mark is cleared here and only here, success or failure, so a
// path is retried only after an attempt finished.
func (h *Hasher) store(exe, sum string, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.inflight, exe)

	// Hashes never expire, they come from the content. Failures are kept apart
	// so a permission error is not retried every tick and so Get stays one map
	// read on the happy path.
	if !ok {
		h.failed[exe] = true
		return
	}
	if len(h.cache)+len(h.failed) >= hashCacheCap {
		h.cache = make(map[string]string, hashCacheCap)
		h.failed = make(map[string]bool)
	}
	h.cache[exe] = sum
}
