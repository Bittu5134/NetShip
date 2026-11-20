package netship

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"time"
)

const (
	hashQueueDepth = 512

	// Far above any real executable on a workstation, far below the point where
	// reading the file becomes a stall. Bigger "executables" are data files or a
	// deleted image path.
	hashMaxSize = 64 << 20

	hashCacheCap = 4096

	hashChunkSize = 1 << 20

	// How long a cached sum is trusted before the file is stat'ed again, so a
	// binary replaced at the same path does not keep its old hash forever.
	hashRecheck = time.Minute

	// A permission error or a file that vanished is not permanent.
	hashFailureTTL = 10 * time.Minute
)

// Hasher is a cache with one worker attached, same shape as Enricher. Callers
// read Get and never wait.
type Hasher struct {
	mu       sync.RWMutex
	cache    map[string]hashEntry
	failed   map[string]time.Time // path -> when the failure stops counting
	inflight map[string]struct{}

	queue chan string
	once  sync.Once
}

type hashEntry struct {
	sum     string
	size    int64
	mod     time.Time
	checked time.Time
}

func NewHasher() *Hasher {
	return &Hasher{
		cache:    make(map[string]hashEntry),
		failed:   make(map[string]time.Time),
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

	// Answer from the cache first. This is called for every socket on every
	// poll, so the stat only happens for a path we do not know, or one we have
	// not looked at in a while.
	h.mu.RLock()
	ent, known := h.cache[exe]
	until, wasFailed := h.failed[exe]
	h.mu.RUnlock()

	if known && time.Since(ent.checked) < hashRecheck {
		return
	}
	if wasFailed && time.Now().Before(until) {
		return
	}

	// Sockets, directories and paths with " (deleted)" in them are not work in
	// the first place.
	st, err := os.Stat(exe)
	if err != nil || !st.Mode().IsRegular() || st.Size() > hashMaxSize {
		return
	}

	h.mu.Lock()
	if cur, ok := h.cache[exe]; ok && cur.size == st.Size() && cur.mod.Equal(st.ModTime()) {
		cur.checked = time.Now()
		h.cache[exe] = cur
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
	ent, ok := h.cache[exe]
	h.mu.RUnlock()
	return ent.sum, ok
}

func (h *Hasher) worker(ctx context.Context) {
	buf := make([]byte, hashChunkSize)
	for {
		select {
		case <-ctx.Done():
			return
		case exe := <-h.queue:
			sum, size, mod, ok := hashFile(exe, buf)
			h.store(exe, sum, size, mod, ok)
		}
	}
}

// The only thing here that touches disk. A partial hash would be worse than no
// hash, so anything that cannot be read to the end reports false.
func hashFile(exe string, buf []byte) (string, int64, time.Time, bool) {
	f, err := os.Open(exe)
	if err != nil {
		return "", 0, time.Time{}, false
	}
	defer f.Close()

	// Checked again after opening: the file can be replaced or grow between the
	// stat in Request and this read.
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > hashMaxSize {
		return "", 0, time.Time{}, false
	}

	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", 0, time.Time{}, false
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), st.ModTime(), true
}

// The in-flight mark is cleared here and only here, success or failure, so a
// path is retried only after an attempt finished.
func (h *Hasher) store(exe, sum string, size int64, mod time.Time, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.inflight, exe)

	if !ok {
		h.failed[exe] = time.Now().Add(hashFailureTTL)
		return
	}
	if len(h.cache)+len(h.failed) >= hashCacheCap {
		h.cache = make(map[string]hashEntry, hashCacheCap)
		h.failed = make(map[string]time.Time)
	}
	h.cache[exe] = hashEntry{sum: sum, size: size, mod: mod, checked: time.Now()}
}
