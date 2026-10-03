// Package aggregator holds bounded, one-second rolling counters in RAM.
// Observe performs no disk, network, or scoring work.
package aggregator

import (
	"hash/fnv"
	"iter"
	"math"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

// Retain a full preceding minute plus the current minute and boundary second.
// Closed-window analysis can run late without new traffic replacing its data.
const bucketCount = 121

type key struct {
	site string
	ip   netip.Addr
}

type Saturation struct {
	Paths         bool
	MissingPaths  bool
	UserAgents    bool
	QueryPatterns bool
	QueryValues   bool
	RecordLimit   bool
	Degraded      bool
}

type Snapshot struct {
	RequestSamples       []model.RequestSample
	SiteID               string
	ClientIP             netip.Addr
	Window               time.Duration
	At                   time.Time
	Requests             uint64
	PeakRPS              uint64
	ActiveSeconds        int
	StatusFamilies       [6]uint64
	ImportantStatuses    map[int]uint64
	Methods              map[string]uint64
	Method404            map[string]uint64
	Method404UniquePaths map[string]int
	MissingUserAgent     uint64
	UserAgentSamples     []string
	UserAgentCounts      map[string]uint64
	PrimaryUserAgent     string
	UserAgentSwitches    uint64
	BytesTotal           uint64
	BytesSamples         uint64
	RequestTimeNanos     uint64
	RequestTimeSamples   uint64
	UpstreamTimeNanos    uint64
	UpstreamTimeSamples  uint64
	RedirectKnown        uint64
	RedirectFollows      uint64
	UniquePaths          int
	Unique404Paths       int
	UserAgents           int
	QueryPatterns        int
	UniqueQueryValues    int
	PathSamples          []string
	MissingPathSamples   []string
	QueryPatternSamples  []string
	Saturation           Saturation
}

type Metrics struct {
	ActiveRecords uint64
	DroppedEvents uint64
	OldEvents     uint64
	Degraded      bool
}

type Identity struct {
	SiteID   string
	ClientIP netip.Addr
}

type Aggregator struct {
	retentionSeconds int64
	sampleSeconds    int64
	mu               sync.Mutex
	limits           config.AggregationConfig
	records          map[key]*record
	sitesByIP        map[netip.Addr]map[string]*record
	totals           [bucketCount]totalBucket
	siteTotals       map[string]*[bucketCount]totalBucket
	drops            [bucketCount]totalBucket
	latest           int64
	lastPrune        int64
	dropped          uint64
	oldEvents        uint64
	degraded         bool
}

type totalBucket struct {
	second         int64
	used           bool
	requests       uint64
	statusFamilies [6]uint64
	statuses       map[int]uint64
	methods        map[string]uint64
	methodHTTP     map[string]MethodHTTP
}

// MethodHTTP retains exact cross totals for each bounded method category.
type MethodHTTP struct {
	Requests  uint64 `json:"requests"`
	Status2xx uint64 `json:"status_2xx"`
	Status301 uint64 `json:"status_301"`
	Status302 uint64 `json:"status_302"`
	Status403 uint64 `json:"status_403"`
	Status404 uint64 `json:"status_404"`
	Status5xx uint64 `json:"status_5xx"`
}

func (m *MethodHTTP) add(other MethodHTTP) {
	m.Requests += other.Requests
	m.Status2xx += other.Status2xx
	m.Status301 += other.Status301
	m.Status302 += other.Status302
	m.Status403 += other.Status403
	m.Status404 += other.Status404
	m.Status5xx += other.Status5xx
}

type record struct {
	samples          []sampleEpoch
	lastSeen         int64
	lastExpired      int64
	lastUA           string
	buckets          [bucketCount]bucket
	paths            map[string]uint16
	missing          map[string]uint16
	agents           map[string]uint16
	queries          map[string]uint16
	queryIDs         map[uint64]uint16
	methodPaths      map[methodPathKey]int64
	pendingRedirects map[string]int64
}

type methodPathKey struct {
	method string
	path   string
}

type bucket struct {
	second          int64
	used            bool
	requests        uint64
	statusFamilies  [6]uint64
	statuses        map[int]uint64
	methods         map[string]uint64
	method404       map[string]uint64
	missingUA       uint64
	uaCounts        map[string]uint64
	uaSwitches      uint64
	bytesTotal      uint64
	bytesSamples    uint64
	requestNanos    uint64
	requestSamples  uint64
	upstreamNanos   uint64
	upstreamSamples uint64
	redirectKnown   uint64
	redirectFollows uint64
	paths           map[string]struct{}
	missing         map[string]struct{}
	agents          map[string]struct{}
	queries         map[string]struct{}
	queryIDs        map[uint64]struct{}
	saturation      Saturation
}

func New(limits config.AggregationConfig, sampleWindow ...time.Duration) *Aggregator {
	seconds := int64(60)
	if len(sampleWindow) > 0 && sampleWindow[0] >= time.Second && sampleWindow[0] <= time.Minute {
		seconds = int64(sampleWindow[0] / time.Second)
	}
	return &Aggregator{retentionSeconds: 61, sampleSeconds: seconds, limits: limits, records: make(map[key]*record), sitesByIP: make(map[netip.Addr]map[string]*record), siteTotals: make(map[string]*[bucketCount]totalBucket)}
}

// RetainClosedWindows reserves an additional minute for recovery analysis.
// Call before ingestion starts. Rich tracking remains bounded by configured caps.
func (a *Aggregator) RetainClosedWindows() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retentionSeconds = bucketCount
}

// Observe counts every parsed request in the server total. An allowlisted
// request does not enter per-IP statistics. The supplied time permits replay.
// It returns false if the event is too old, invalid, or hits the record cap.
func (a *Aggregator) Observe(event model.RequestEvent, allowlisted bool, at time.Time) bool {
	if !event.ClientIP.IsValid() || event.SiteID == "" || event.Status < 100 || event.Status > 599 {
		return false
	}
	event.ClientIP = event.ClientIP.Unmap()
	second := at.Unix()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.latest != 0 && second < a.latest-(a.retentionSeconds-1) {
		a.oldEvents++
		return false
	}
	if second > a.latest {
		a.latest = second
	}
	if second > a.lastPrune {
		a.prune(second)
		a.lastPrune = second
	}
	addTotal(&a.totals[slot(second)], event, second)
	if sites := a.siteTotals[event.SiteID]; sites != nil {
		addTotal(&sites[slot(second)], event, second)
	} else if len(a.siteTotals) < 128 {
		sites = new([bucketCount]totalBucket)
		a.siteTotals[event.SiteID] = sites
		addTotal(&sites[slot(second)], event, second)
	}
	if allowlisted {
		return true
	}
	globalKey := key{ip: event.ClientIP}
	siteKey := key{site: event.SiteID, ip: event.ClientIP}
	needed := 0
	if a.records[globalKey] == nil {
		needed++
	}
	if a.records[siteKey] == nil {
		needed++
	}
	if len(a.records)+needed > a.limits.MaxActiveRecords {
		a.dropped++
		counter := &a.drops[slot(second)]
		if !counter.used || counter.second != second {
			*counter = totalBucket{second: second, used: true}
		}
		counter.requests++
		return false
	}
	var requestSample model.RequestSample
	if !a.degraded && a.sampleSeconds > 0 {
		requestSample = model.SampleRequest(event)
	}
	for _, id := range []key{globalKey, siteKey} {
		rec := a.records[id]
		if rec == nil {
			rec = &record{
				paths: make(map[string]uint16), missing: make(map[string]uint16),
				agents: make(map[string]uint16), queries: make(map[string]uint16), queryIDs: make(map[uint64]uint16), methodPaths: make(map[methodPathKey]int64), pendingRedirects: make(map[string]int64),
			}
			epochs := 2
			if a.retentionSeconds > 61 {
				epochs = int((a.retentionSeconds-1)/a.sampleSeconds) + 2
			}
			rec.samples = make([]sampleEpoch, epochs)
			a.records[id] = rec
			if id.site != "" {
				if a.sitesByIP[id.ip] == nil {
					a.sitesByIP[id.ip] = make(map[string]*record)
				}
				a.sitesByIP[id.ip][id.site] = rec
			}
		}
		rec.add(event, second, a.limits, a.degraded, a.retentionSeconds)
		if !a.degraded && a.sampleSeconds > 0 {
			rec.sample(requestSample, at, a.sampleSeconds)
		}
	}
	return true
}

func addTotal(bucket *totalBucket, event model.RequestEvent, second int64) {
	if !bucket.used || bucket.second != second {
		*bucket = totalBucket{second: second, used: true, statuses: make(map[int]uint64), methods: make(map[string]uint64), methodHTTP: make(map[string]MethodHTTP)}
	}
	bucket.requests++
	bucket.statusFamilies[event.Status/100]++
	switch event.Status {
	case 301, 302, 403, 404:
		bucket.statuses[event.Status]++
	}
	method := event.Method
	if len(method) > 32 || (bucket.methods[method] == 0 && len(bucket.methods) >= 16) {
		method = "OTHER"
	}
	bucket.methods[method]++
	row := bucket.methodHTTP[method]
	row.Requests++
	switch event.Status {
	case 301:
		row.Status301++
	case 302:
		row.Status302++
	case 403:
		row.Status403++
	case 404:
		row.Status404++
	}
	if event.Status/100 == 2 {
		row.Status2xx++
	}
	if event.Status/100 == 5 {
		row.Status5xx++
	}
	bucket.methodHTTP[method] = row
}

func (a *Aggregator) Snapshot(site string, ip netip.Addr, window time.Duration, at time.Time) (Snapshot, bool) {
	result := Snapshot{SiteID: site, ClientIP: ip.Unmap(), Window: window, At: at,
		ImportantStatuses: make(map[int]uint64), Methods: make(map[string]uint64), Method404: make(map[string]uint64),
		Method404UniquePaths: make(map[string]int), UserAgentCounts: make(map[string]uint64)}
	seconds := int64(window / time.Second)
	if seconds < 1 || seconds > 60 || window%time.Second != 0 {
		return result, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if at.Unix() > a.lastPrune {
		a.prune(at.Unix())
		a.lastPrune = at.Unix()
	}
	rec := a.records[key{site: site, ip: ip.Unmap()}]
	if rec == nil {
		return result, false
	}
	cutoff := at.Unix() - seconds + 1
	result.RequestSamples = rec.requestSamples(cutoff, at)
	paths := make(map[string]struct{})
	missing := make(map[string]struct{})
	agents := make(map[string]struct{})
	queries := make(map[string]struct{})
	queryIDs := make(map[uint64]struct{})
	for i := range rec.buckets {
		b := &rec.buckets[i]
		if !b.used || b.second < cutoff || b.second > at.Unix() {
			continue
		}
		result.Requests += b.requests
		if b.requests > result.PeakRPS {
			result.PeakRPS = b.requests
		}
		if b.requests > 0 {
			result.ActiveSeconds++
		}
		for family, count := range b.statusFamilies {
			result.StatusFamilies[family] += count
		}
		for status, count := range b.statuses {
			result.ImportantStatuses[status] += count
		}
		for method, count := range b.methods {
			result.Methods[method] += count
		}
		for method, count := range b.method404 {
			result.Method404[method] += count
		}
		result.MissingUserAgent += b.missingUA
		result.UserAgentSwitches += b.uaSwitches
		for ua, count := range b.uaCounts {
			result.UserAgentCounts[ua] += count
		}
		result.BytesTotal = saturatingAdd(result.BytesTotal, b.bytesTotal)
		result.BytesSamples += b.bytesSamples
		result.RequestTimeNanos = saturatingAdd(result.RequestTimeNanos, b.requestNanos)
		result.RequestTimeSamples += b.requestSamples
		result.UpstreamTimeNanos = saturatingAdd(result.UpstreamTimeNanos, b.upstreamNanos)
		result.UpstreamTimeSamples += b.upstreamSamples
		result.RedirectKnown += b.redirectKnown
		result.RedirectFollows += b.redirectFollows
		for value := range b.paths {
			paths[value] = struct{}{}
		}
		for value := range b.missing {
			missing[value] = struct{}{}
		}
		for value := range b.agents {
			agents[value] = struct{}{}
		}
		for value := range b.queries {
			queries[value] = struct{}{}
		}
		for value := range b.queryIDs {
			queryIDs[value] = struct{}{}
		}
		result.Saturation.Paths = result.Saturation.Paths || b.saturation.Paths
		result.Saturation.MissingPaths = result.Saturation.MissingPaths || b.saturation.MissingPaths
		result.Saturation.UserAgents = result.Saturation.UserAgents || b.saturation.UserAgents
		result.Saturation.QueryPatterns = result.Saturation.QueryPatterns || b.saturation.QueryPatterns
		result.Saturation.QueryValues = result.Saturation.QueryValues || b.saturation.QueryValues
		result.Saturation.Degraded = result.Saturation.Degraded || b.saturation.Degraded
	}
	result.UniquePaths = len(paths)
	result.Unique404Paths = len(missing)
	result.UserAgents = len(agents)
	result.QueryPatterns = len(queries)
	result.UniqueQueryValues = len(queryIDs)
	result.PathSamples = sortedKeys(paths)
	result.MissingPathSamples = sortedKeys(missing)
	result.QueryPatternSamples = sortedKeys(queries)
	result.UserAgentSamples = sortedKeys(agents)
	for pair, lastSeen := range rec.methodPaths {
		if lastSeen >= cutoff && lastSeen <= at.Unix() {
			result.Method404UniquePaths[pair.method]++
		}
	}
	for _, ua := range result.UserAgentSamples {
		if result.PrimaryUserAgent == "" || result.UserAgentCounts[ua] > result.UserAgentCounts[result.PrimaryUserAgent] {
			result.PrimaryUserAgent = ua
		}
	}
	for _, drop := range a.drops {
		if drop.used && drop.second >= cutoff && drop.second <= at.Unix() && drop.requests > 0 {
			result.Saturation.RecordLimit = true
			break
		}
	}
	return result, true
}

func (a *Aggregator) TotalRequests(window time.Duration, at time.Time) uint64 {
	seconds := int64(window / time.Second)
	if seconds < 1 || seconds > 60 || window%time.Second != 0 {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := at.Unix() - seconds + 1
	var total uint64
	for _, bucket := range a.totals {
		if bucket.used && bucket.second >= cutoff && bucket.second <= at.Unix() {
			total += bucket.requests
		}
	}
	return total
}

func (a *Aggregator) SiteCount(ip netip.Addr, window time.Duration, at time.Time) int {
	seconds := int64(window / time.Second)
	if seconds < 1 || seconds > 60 || window%time.Second != 0 {
		return 0
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := at.Unix() - seconds + 1
	count := 0
	for _, rec := range a.sitesByIP[ip.Unmap()] {
		for _, b := range rec.buckets {
			if b.used && b.second >= cutoff && b.second <= at.Unix() && b.requests > 0 {
				count++
				break
			}
		}
	}
	return count
}

// AnalysisSnapshots makes one candidate pass for a fixed window. Individual
// snapshots are copied under short locks; detector/output work in the consumer
// never holds the ingestion mutex. Site counts use the per-IP index, and pruning
// runs at most once for this timestamp. No full batch of rich snapshots is kept.
func (a *Aggregator) AnalysisSnapshots(window time.Duration, at time.Time) iter.Seq2[Snapshot, int] {
	return func(yield func(Snapshot, int) bool) {
		for _, id := range a.ActiveIdentities(window, at) {
			snapshot, ok := a.Snapshot(id.SiteID, id.ClientIP, window, at)
			if !ok || snapshot.Requests == 0 {
				continue
			}
			sites := 0
			if id.SiteID == "" {
				sites = a.SiteCount(id.ClientIP, window, at)
			}
			if !yield(snapshot, sites) {
				return
			}
		}
	}
}

// ActiveIdentities returns bounded candidates for periodic deep analysis.
func (a *Aggregator) ActiveIdentities(window time.Duration, at time.Time) []Identity {
	seconds := int64(window / time.Second)
	if seconds < 1 || seconds > 60 || window%time.Second != 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	cutoff := at.Unix() - seconds + 1
	result := make([]Identity, 0, len(a.records))
	for id, rec := range a.records {
		for _, b := range rec.buckets {
			if b.used && b.second >= cutoff && b.second <= at.Unix() && b.requests > 0 {
				result = append(result, Identity{SiteID: id.site, ClientIP: id.ip})
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].SiteID == result[j].SiteID {
			return result[i].ClientIP.Compare(result[j].ClientIP) < 0
		}
		return result[i].SiteID < result[j].SiteID
	})
	return result
}

func (a *Aggregator) Metrics() Metrics {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Metrics{ActiveRecords: uint64(len(a.records)), DroppedEvents: a.dropped, OldEvents: a.oldEvents, Degraded: a.degraded}
}

func (a *Aggregator) SetDegraded(value bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.degraded == value {
		return false
	}
	a.degraded = value
	return true
}

// Prune releases client records after their 60-second window expires even when
// no new requests arrive. The daemon calls this periodically.
func (a *Aggregator) Prune(at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(at.Unix())
}

func (a *Aggregator) prune(second int64) {
	for id, rec := range a.records {
		if rec.lastSeen < second-(a.retentionSeconds-1) {
			delete(a.records, id)
			if id.site != "" {
				delete(a.sitesByIP[id.ip], id.site)
				if len(a.sitesByIP[id.ip]) == 0 {
					delete(a.sitesByIP, id.ip)
				}
			}
		}
	}
}

func (r *record) add(event model.RequestEvent, second int64, limits config.AggregationConfig, degraded bool, retentionSeconds int64) {
	if second > r.lastExpired {
		r.expireBefore(second - (retentionSeconds - 1))
		r.lastExpired = second
	}
	if second > r.lastSeen {
		r.lastSeen = second
	}
	b := &r.buckets[slot(second)]
	if !b.used || b.second != second {
		if b.used {
			release(r.paths, b.paths)
			release(r.missing, b.missing)
			release(r.agents, b.agents)
			release(r.queries, b.queries)
			releaseHashes(r.queryIDs, b.queryIDs)
		}
		*b = bucket{second: second, used: true, statuses: make(map[int]uint64), methods: make(map[string]uint64), method404: make(map[string]uint64), uaCounts: make(map[string]uint64)}
	}
	b.requests++
	if degraded {
		b.saturation.Degraded = true
	}
	// Basic counters remain exact when rich tracking is suspended.
	b.statusFamilies[event.Status/100]++
	switch event.Status {
	case 301, 302, 403, 404:
		b.statuses[event.Status]++
	}
	method := event.Method
	if len(method) > 32 || (b.methods[method] == 0 && len(b.methods) >= 16) {
		method = "OTHER"
	}
	b.methods[method]++
	if event.Status == 404 {
		b.method404[method]++
	}
	if event.UserAgent == nil || *event.UserAgent == "" {
		b.missingUA++
	}
	if event.Bytes != nil && *event.Bytes >= 0 {
		b.bytesTotal = saturatingAdd(b.bytesTotal, uint64(*event.Bytes))
		b.bytesSamples++
	}
	if event.RequestTime != nil && *event.RequestTime >= 0 {
		b.requestNanos = saturatingAdd(b.requestNanos, uint64(*event.RequestTime))
		b.requestSamples++
	}
	if event.UpstreamTime != nil && *event.UpstreamTime >= 0 {
		b.upstreamNanos = saturatingAdd(b.upstreamNanos, uint64(*event.UpstreamTime))
		b.upstreamSamples++
	}
	if degraded {
		return
	}
	// Reject oversized evidence before canonicalization or query parsing. A
	// single hostile access-log line may otherwise be much larger than the
	// configured per-value retention limit.
	path := ""
	if len(event.Path) <= limits.MaxValueBytes {
		path = CanonicalPath(event.Path)
	} else {
		b.saturation.Paths = true
		if event.Status == 404 {
			b.saturation.MissingPaths = true
		}
	}
	followKey := path
	if path != "" && event.Query != "" && len(event.Query) <= limits.MaxValueBytes {
		if values, err := url.ParseQuery(event.Query); err == nil {
			followKey += "?" + values.Encode()
		}
	}
	if path != "" {
		if _, found := r.pendingRedirects[followKey]; found {
			b.redirectFollows++
			delete(r.pendingRedirects, followKey)
		} else if _, found := r.pendingRedirects[path]; found {
			b.redirectFollows++
			delete(r.pendingRedirects, path)
		}
	}
	if (event.Status == 301 || event.Status == 302) && event.Location != nil {
		if target := redirectTarget(*event.Location, event.Host, limits.MaxValueBytes); target != "" {
			b.redirectKnown++
			if _, found := r.pendingRedirects[target]; found || len(r.pendingRedirects) < limits.MaxPathsPerIP {
				r.pendingRedirects[target] = second
			}
		}
	}
	addBounded(path, &b.paths, r.paths, limits.MaxPathsPerIP, limits.MaxValueBytes, &b.saturation.Paths)
	if event.Status == 404 {
		addBounded(path, &b.missing, r.missing, limits.Max404PathsPerIP, limits.MaxValueBytes, &b.saturation.MissingPaths)
	}
	if event.UserAgent != nil {
		if addBounded(*event.UserAgent, &b.agents, r.agents, limits.MaxUserAgentsPerIP, limits.MaxValueBytes, &b.saturation.UserAgents) {
			b.uaCounts[*event.UserAgent]++
			if r.lastUA != "" && r.lastUA != *event.UserAgent {
				b.uaSwitches++
			}
			r.lastUA = *event.UserAgent
		}
	}
	if event.Query != "" {
		if len(event.Query) > limits.MaxValueBytes || path == "" {
			b.saturation.QueryPatterns = true
		} else {
			addBounded(queryPattern(path, event.Query), &b.queries, r.queries, limits.MaxQueriesPerIP, limits.MaxValueBytes, &b.saturation.QueryPatterns)
			fingerprint := fnv.New64a()
			fingerprint.Write([]byte(path))
			fingerprint.Write([]byte{'?'})
			if values, err := url.ParseQuery(event.Query); err == nil {
				fingerprint.Write([]byte(values.Encode()))
				addHash(fingerprint.Sum64(), &b.queryIDs, r.queryIDs, limits.MaxQueriesPerIP, &b.saturation.QueryValues)
			}
		}
	}
	if event.Status == 404 {
		if _, retained := b.missing[path]; retained {
			pair := methodPathKey{method: method, path: path}
			if _, seen := r.methodPaths[pair]; seen || len(r.methodPaths) < limits.Max404PathsPerIP {
				r.methodPaths[pair] = second
			}
		}
	}
}

func (r *record) expireBefore(cutoff int64) {
	for target, lastSeen := range r.pendingRedirects {
		if lastSeen < cutoff {
			delete(r.pendingRedirects, target)
		}
	}
	for pair, lastSeen := range r.methodPaths {
		if lastSeen < cutoff {
			delete(r.methodPaths, pair)
		}
	}
	for i := range r.buckets {
		b := &r.buckets[i]
		if !b.used || b.second >= cutoff {
			continue
		}
		release(r.paths, b.paths)
		release(r.missing, b.missing)
		release(r.agents, b.agents)
		release(r.queries, b.queries)
		releaseHashes(r.queryIDs, b.queryIDs)
		*b = bucket{}
	}
}

func addBounded(value string, bucketValues *map[string]struct{}, refs map[string]uint16, limit, maxBytes int, saturated *bool) bool {
	if value == "" {
		return false
	}
	if len(value) > maxBytes {
		*saturated = true
		return false
	}
	if *bucketValues != nil {
		if _, found := (*bucketValues)[value]; found {
			return true
		}
	}
	if _, found := refs[value]; !found && len(refs) >= limit {
		*saturated = true
		return false
	}
	if *bucketValues == nil {
		*bucketValues = make(map[string]struct{})
	}
	(*bucketValues)[value] = struct{}{}
	refs[value]++
	return true
}

func release(refs map[string]uint16, values map[string]struct{}) {
	for value := range values {
		if refs[value] <= 1 {
			delete(refs, value)
		} else {
			refs[value]--
		}
	}
}

func addHash(value uint64, bucketValues *map[uint64]struct{}, refs map[uint64]uint16, limit int, saturated *bool) {
	if *bucketValues != nil {
		if _, found := (*bucketValues)[value]; found {
			return
		}
	}
	if _, found := refs[value]; !found && len(refs) >= limit {
		*saturated = true
		return
	}
	if *bucketValues == nil {
		*bucketValues = make(map[uint64]struct{})
	}
	(*bucketValues)[value] = struct{}{}
	refs[value]++
}

func releaseHashes(refs map[uint64]uint16, values map[uint64]struct{}) {
	for value := range values {
		if refs[value] <= 1 {
			delete(refs, value)
		} else {
			refs[value]--
		}
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func queryPattern(path, raw string) string {
	parts := strings.Split(raw, "&")
	keys := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		key, value, _ := strings.Cut(part, "=")
		if key != "" {
			if decoded, err := url.QueryUnescape(key); err == nil {
				key = url.QueryEscape(decoded)
			}
			decoded, err := url.QueryUnescape(value)
			if err == nil {
				value = decoded
			}
			marker := "{VALUE}"
			if isDigits(value) {
				marker = "{NUMBER}"
			}
			keys[key+"="+marker] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	return path + "?" + strings.Join(ordered, "&")
}

// CanonicalPath decodes percent-encoded unreserved bytes only. Encoded slash
// and other reserved characters retain their path meaning and are not merged
// with literal separators; percent hex case is normalized.
func CanonicalPath(path string) string {
	var result strings.Builder
	result.Grow(len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '%' && i+2 < len(path) {
			high, okHigh := hexNibble(path[i+1])
			low, okLow := hexNibble(path[i+2])
			if okHigh && okLow {
				decoded := high<<4 | low
				if unreserved(decoded) {
					result.WriteByte(decoded)
				} else {
					result.WriteByte('%')
					result.WriteByte("0123456789ABCDEF"[high])
					result.WriteByte("0123456789ABCDEF"[low])
				}
				i += 2
				continue
			}
		}
		result.WriteByte(path[i])
	}
	return result.String()
}

func redirectTarget(location, requestHost string, maxBytes int) string {
	parsed, err := url.Parse(location)
	if err != nil || parsed == nil {
		return ""
	}
	if parsed.Host != "" && (requestHost == "" || !strings.EqualFold(parsed.Host, requestHost)) {
		return ""
	}
	path := parsed.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		return ""
	}
	result := CanonicalPath(path)
	if parsed.RawQuery != "" {
		values, err := url.ParseQuery(parsed.RawQuery)
		if err != nil {
			return ""
		}
		result += "?" + values.Encode()
	}
	if len(result) > maxBytes {
		return ""
	}
	return result
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func unreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_' || value == '~'
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func slot(second int64) int {
	index := second % bucketCount
	if index < 0 {
		index += bucketCount
	}
	return int(index)
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
