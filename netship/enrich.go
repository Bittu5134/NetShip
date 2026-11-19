package netship

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ASNInfo struct {
	ASN     int    `json:"asn"`
	Org     string `json:"org"`
	Country string `json:"country"`
	Hosting bool   `json:"hosting"`
}

const (
	// ASN ownership changes on the scale of months.
	asnCacheTTL = 24 * time.Hour
	// Short, because "no answer" is not a fact, and one dead resolver must not
	// turn the poll loop into a DNS flood.
	asnNegativeTTL = 10 * time.Minute
	asnCacheCap    = 20000

	// Request must never block the poller: a full queue drops the overflow,
	// which costs one enrichment, not a tick.
	enrichQueueDepth = 4096
	enrichWorkers    = 2

	enrichLookupTimeout = 3 * time.Second

	asnOriginV4Suffix = ".origin.asn.cymru.com"
	asnOriginV6Suffix = ".origin6.asn.cymru.com"
	asnOrgSuffix      = ".asn.cymru.com"
)

// ASNs that mean "infrastructure, not a person", for when Cymru returns no org
// name. Only ever used to suppress ("this is boring"), never as evidence that a
// destination is safe. Residential ISPs are left out on purpose, 4134
// (Chinanet) in particular.
var hostingASN = map[int]string{
	16509:  "Amazon AWS",
	14618:  "Amazon",
	8987:   "Amazon",
	15169:  "Google",
	396982: "Google Cloud",
	19527:  "Google",
	8075:   "Microsoft Azure",
	8068:   "Microsoft",
	13335:  "Cloudflare",
	20940:  "Akamai",
	16625:  "Akamai",
	54113:  "Fastly",
	22822:  "Limelight",
	60068:  "Datacamp / CDN77",
	14061:  "DigitalOcean",
	16276:  "OVH",
	24940:  "Hetzner",
	63949:  "Linode / Akamai",
	20473:  "Vultr / Constant",
	12876:  "Scaleway",
	51167:  "Contabo",
	49505:  "Selectel",
	9009:   "M247",
	202425: "IP Volume",
	210644: "Aeza",
	47890:  "Unmanaged Ltd",
	29802:  "HIVELOCITY",
	36352:  "ColoCrossing",
	53667:  "FranTech / BuyVM",
	45102:  "Alibaba",
	37963:  "Alibaba",
	132203: "Tencent",
	55990:  "Huawei",
}

type Enricher struct {
	disabled bool

	// Set to receive one line per dropped or failed lookup.
	Debug func(msg string)

	resolver *net.Resolver

	mu       sync.RWMutex
	cache    map[string]asnCacheEntry
	inflight map[string]struct{}

	queue chan string
	once  sync.Once

	lookups atomic.Int64
}

type asnCacheEntry struct {
	info    ASNInfo
	expires time.Time
	// valid is "asked, got an answer" as opposed to "asked, got nothing".
	valid bool
}

// Disabled still answers Cached and Lookups, it just never touches DNS. That is
// what makes offline mode honest instead of quiet.
func NewEnricher(disabled bool) *Enricher {
	return &Enricher{
		disabled: disabled,
		resolver: net.DefaultResolver,
		cache:    make(map[string]asnCacheEntry),
		inflight: make(map[string]struct{}),
		queue:    make(chan string, enrichQueueDepth),
	}
}

func (e *Enricher) Start(ctx context.Context) {
	if e == nil || e.disabled {
		return
	}
	e.once.Do(func() {
		for i := 0; i < enrichWorkers; i++ {
			go e.worker(ctx)
		}
	})
}

// Request is safe to call every tick for every socket.
func (e *Enricher) Request(ip string) {
	if e == nil || e.disabled {
		return
	}
	ip = strings.TrimSpace(ip)
	if ip == "" || IsPrivateOrLocal(ip) {
		return
	}

	now := time.Now()
	e.mu.Lock()
	if ent, ok := e.cache[ip]; ok && now.Before(ent.expires) {
		e.mu.Unlock()
		return
	}
	if _, busy := e.inflight[ip]; busy {
		e.mu.Unlock()
		return
	}
	e.inflight[ip] = struct{}{}
	e.mu.Unlock()

	select {
	case e.queue <- ip:
	default:
		// Drop the in-flight mark too, or this IP is never retried.
		e.mu.Lock()
		delete(e.inflight, ip)
		e.mu.Unlock()
		if e.Debug != nil {
			e.Debug("enrich: queue full, dropped " + ip)
		}
	}
}

func (e *Enricher) Cached(ip string) (ASNInfo, bool) {
	if e == nil {
		return ASNInfo{}, false
	}
	e.mu.RLock()
	ent, ok := e.cache[ip]
	e.mu.RUnlock()
	if !ok || !ent.valid || !time.Now().Before(ent.expires) {
		return ASNInfo{}, false
	}
	return ent.info, true
}

func (e *Enricher) Lookups() int {
	if e == nil {
		return 0
	}
	return int(e.lookups.Load())
}

func (e *Enricher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-e.queue:
			e.process(ctx, ip)
		}
	}
}

func (e *Enricher) process(ctx context.Context, ip string) {
	info, ok := e.lookupASN(ctx, ip)
	e.lookups.Add(1)
	e.store(ip, info, ok)
	if !ok && e.Debug != nil && ctx.Err() == nil {
		e.Debug("enrich: no ASN for " + ip)
	}
}

func (e *Enricher) store(ip string, info ASNInfo, ok bool) {
	now := time.Now()
	ttl := asnCacheTTL
	if !ok {
		ttl = asnNegativeTTL
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.inflight, ip)
	if len(e.cache) >= asnCacheCap {
		e.evictLocked(now)
	}
	e.cache[ip] = asnCacheEntry{info: info, expires: now.Add(ttl), valid: ok}
}

// Expired entries first, they are free to drop. If that is still not enough the
// table goes wholesale: an LRU order costs more than the re-lookups it saves.
func (e *Enricher) evictLocked(now time.Time) {
	for k, ent := range e.cache {
		if !now.Before(ent.expires) {
			delete(e.cache, k)
		}
	}
	if len(e.cache) >= asnCacheCap {
		e.cache = make(map[string]asnCacheEntry, asnCacheCap)
	}
}

// The only place here that touches DNS. Origin gives ASN and country, the org
// query gives the name, both from Team Cymru over plain DNS: no key to leak and
// no HTTP to sit behind.
func (e *Enricher) lookupASN(ctx context.Context, ip string) (ASNInfo, bool) {
	var info ASNInfo

	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return info, false
	}
	// A v4-mapped v6 address is a v4 address with extra ceremony, and Cymru
	// only serves the v4 tree for it.
	if v4 := parsed.To4(); v4 != nil {
		parsed = v4
	}

	qname, ok := originQueryName(parsed)
	if !ok {
		return info, false
	}
	txt, ok := e.queryTXT(ctx, qname)
	if !ok {
		return info, false
	}
	info, ok = parseOriginTXT(txt)
	if !ok {
		return ASNInfo{}, false
	}

	if org, country, ok := e.lookupOrg(ctx, info.ASN); ok {
		info.Org = org
		if info.Country == "" {
			info.Country = country
		}
	}

	if provider, hosting := hostingASN[info.ASN]; hosting {
		info.Hosting = true
		if info.Org == "" {
			info.Org = provider
		}
	}
	return info, true
}

func (e *Enricher) queryTXT(ctx context.Context, name string) (string, bool) {
	lctx, cancel := context.WithTimeout(ctx, enrichLookupTimeout)
	defer cancel()

	answers, err := e.resolver.LookupTXT(lctx, name)
	if err != nil {
		return "", false
	}
	for _, a := range answers {
		if strings.TrimSpace(a) != "" {
			return a, true
		}
	}
	return "", false
}

func (e *Enricher) lookupOrg(ctx context.Context, asn int) (string, string, bool) {
	txt, ok := e.queryTXT(ctx, fmt.Sprintf("AS%d%s", asn, asnOrgSuffix))
	if !ok {
		return "", "", false
	}
	fields := strings.Split(txt, "|")
	if len(fields) < 5 {
		return "", "", false
	}
	country := strings.ToUpper(strings.TrimSpace(fields[1]))
	// Everything after field four is the name: provider names contain spaces
	// and commas.
	org := strings.TrimSpace(strings.Join(fields[4:], "|"))
	if country != "" {
		org = strings.TrimSpace(strings.TrimSuffix(org, ", "+country))
	}
	if org == "" {
		return "", country, false
	}
	return org, country, true
}

func parseOriginTXT(txt string) (ASNInfo, bool) {
	fields := strings.Split(txt, "|")
	if len(fields) < 3 {
		return ASNInfo{}, false
	}
	// Field 0 can list several candidate origins. The first one is the covering
	// prefix and the only one worth showing.
	asnTokens := strings.Fields(fields[0])
	if len(asnTokens) == 0 {
		return ASNInfo{}, false
	}
	asn, err := strconv.Atoi(asnTokens[0])
	if err != nil || asn <= 0 {
		return ASNInfo{}, false
	}
	return ASNInfo{
		ASN:     asn,
		Country: strings.ToUpper(strings.TrimSpace(fields[2])),
	}, true
}

func originQueryName(ip net.IP) (string, bool) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d%s", v4[3], v4[2], v4[1], v4[0], asnOriginV4Suffix), true
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(64 + len(asnOriginV6Suffix))
	for i := len(v6) - 1; i >= 0; i-- {
		if i != len(v6)-1 {
			b.WriteByte('.')
		}
		// Low nibble first, because reversing the address reverses the nibbles.
		b.WriteByte(hexDigits[v6[i]&0x0f])
		b.WriteByte('.')
		b.WriteByte(hexDigits[v6[i]>>4])
	}
	b.WriteString(asnOriginV6Suffix)
	return b.String(), true
}

// Addresses that cannot have a useful ASN, so looking them up only burns DNS.
// Garbage counts as local: the quiet path, not an error path.
func IsPrivateOrLocal(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return true
	}
	if v4 := parsed.To4(); v4 != nil {
		parsed = v4
		if isCarrierNAT(v4) {
			return true
		}
	}
	return parsed.IsLoopback() ||
		parsed.IsPrivate() ||
		parsed.IsUnspecified() ||
		parsed.IsMulticast() ||
		parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() ||
		parsed.IsInterfaceLocalMulticast()
}

// 100.64.0.0/10, which no ASN lookup helps with.
func isCarrierNAT(v4 net.IP) bool {
	return len(v4) == 4 && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}
