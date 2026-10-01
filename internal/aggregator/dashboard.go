package aggregator

import (
	"net/netip"
	"sort"
	"time"
)

// DashboardView is a bounded read model over the same rolling buckets used by
// detection. Server/site request and HTTP counters include allowlisted traffic;
// IP detail covers tracked clients only.
type DashboardView struct {
	At                time.Time                `json:"at"`
	WindowSeconds     int                      `json:"window_seconds"`
	Requests          uint64                   `json:"requests"`
	RequestsPerSecond uint64                   `json:"requests_per_second"`
	ActiveIPs         int                      `json:"active_ips"`
	StatusFamilies    [6]uint64                `json:"status_families"`
	Statuses          map[int]uint64           `json:"statuses"`
	Methods           map[string]uint64        `json:"methods"`
	MethodHTTP        map[string]MethodHTTP    `json:"method_http"`
	Sites             []DashboardSite          `json:"sites"`
	TopIPs            []DashboardIP            `json:"top_ips"`
	WindowDropped     uint64                   `json:"window_dropped"`
	Degraded          bool                     `json:"degraded"`
	SiteIPs           map[string][]DashboardIP `json:"-"`
}

type DashboardSite struct {
	SiteID          string                `json:"site_id"`
	Requests        uint64                `json:"requests"`
	ActiveIPs       int                   `json:"active_ips"`
	RecentIncidents int                   `json:"recent_incidents"`
	SuspiciousIPs   int                   `json:"suspicious_ips"`
	WouldBlockIPs   int                   `json:"would_block_ips"`
	StatusFamilies  [6]uint64             `json:"status_families"`
	Statuses        map[int]uint64        `json:"statuses"`
	Methods         map[string]uint64     `json:"methods"`
	MethodHTTP      map[string]MethodHTTP `json:"method_http"`
}

type DashboardIP struct {
	IP                 netip.Addr        `json:"ip"`
	SiteID             string            `json:"site_id,omitempty"`
	SiteIDs            []string          `json:"site_ids,omitempty"`
	Requests           uint64            `json:"requests"`
	PeakRPS            uint64            `json:"peak_rps"`
	NotFound           uint64            `json:"status_404"`
	Unique404Paths     int               `json:"unique_404_paths"`
	MissingUserAgent   uint64            `json:"missing_user_agent"`
	PathSamples        []string          `json:"path_samples,omitempty"`
	MissingPathSamples []string          `json:"missing_path_samples,omitempty"`
	QueryPatterns      []string          `json:"query_patterns,omitempty"`
	UserAgents         []string          `json:"user_agents,omitempty"`
	UserAgentRequests  map[string]uint64 `json:"user_agent_requests,omitempty"`
	Saturation         Saturation        `json:"saturation"`
}

type candidate struct {
	id     key
	record *record
	view   DashboardIP
}

// Dashboard summarizes at most 60 seconds and returns at most limit IPs per
// collection. It holds the aggregator lock for one bounded record scan; no
// database, network, or detector work occurs under that lock.
func (a *Aggregator) Dashboard(window time.Duration, at time.Time, limit int) DashboardView {
	if window < time.Second || window > 60*time.Second || window%time.Second != 0 {
		window = 60 * time.Second
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	view := DashboardView{At: at, WindowSeconds: int(window / time.Second), Statuses: make(map[int]uint64), Methods: make(map[string]uint64), MethodHTTP: make(map[string]MethodHTTP), SiteIPs: make(map[string][]DashboardIP)}
	cutoff := at.Unix() - int64(view.WindowSeconds) + 1
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(at.Unix())
	view.Degraded = a.degraded
	for _, bucket := range a.totals {
		if !bucket.used || bucket.second < cutoff || bucket.second > at.Unix() {
			continue
		}
		view.Requests += bucket.requests
		for family, count := range bucket.statusFamilies {
			view.StatusFamilies[family] += count
		}
		for status, count := range bucket.statuses {
			view.Statuses[status] += count
		}
		for method, count := range bucket.methods {
			view.Methods[method] += count
		}
		for method, counts := range bucket.methodHTTP {
			row := view.MethodHTTP[method]
			row.add(counts)
			view.MethodHTTP[method] = row
		}
		if bucket.second == at.Unix()-1 {
			view.RequestsPerSecond = bucket.requests
		}
	}
	for _, bucket := range a.drops {
		if bucket.used && bucket.second >= cutoff && bucket.second <= at.Unix() {
			view.WindowDropped += bucket.requests
		}
	}
	for site, buckets := range a.siteTotals {
		item := DashboardSite{SiteID: site, Statuses: make(map[int]uint64), Methods: make(map[string]uint64), MethodHTTP: make(map[string]MethodHTTP)}
		for _, bucket := range buckets {
			if !bucket.used || bucket.second < cutoff || bucket.second > at.Unix() {
				continue
			}
			item.Requests += bucket.requests
			for family, count := range bucket.statusFamilies {
				item.StatusFamilies[family] += count
			}
			for status, count := range bucket.statuses {
				item.Statuses[status] += count
			}
			for method, count := range bucket.methods {
				item.Methods[method] += count
			}
			for method, counts := range bucket.methodHTTP {
				row := item.MethodHTTP[method]
				row.add(counts)
				item.MethodHTTP[method] = row
			}
		}
		view.Sites = append(view.Sites, item)
	}
	index := make(map[string]int, len(view.Sites))
	for i, item := range view.Sites {
		index[item.SiteID] = i
	}
	global := make([]candidate, 0, len(a.records)/2)
	bySite := make(map[string][]candidate)
	sitesByIP := make(map[netip.Addr][]string)
	for id, record := range a.records {
		item := DashboardIP{IP: id.ip, SiteID: id.site}
		for _, bucket := range record.buckets {
			if !bucket.used || bucket.second < cutoff || bucket.second > at.Unix() {
				continue
			}
			item.Requests += bucket.requests
			item.NotFound += bucket.statuses[404]
			item.MissingUserAgent += bucket.missingUA
			if bucket.requests > item.PeakRPS {
				item.PeakRPS = bucket.requests
			}
			item.Saturation.Degraded = item.Saturation.Degraded || bucket.saturation.Degraded
			item.Saturation.Paths = item.Saturation.Paths || bucket.saturation.Paths
			item.Saturation.MissingPaths = item.Saturation.MissingPaths || bucket.saturation.MissingPaths
			item.Saturation.UserAgents = item.Saturation.UserAgents || bucket.saturation.UserAgents
			item.Saturation.QueryPatterns = item.Saturation.QueryPatterns || bucket.saturation.QueryPatterns
		}
		if item.Requests == 0 {
			continue
		}
		entry := candidate{id: id, record: record, view: item}
		if id.site == "" {
			global = append(global, entry)
			view.ActiveIPs++
		} else {
			bySite[id.site] = append(bySite[id.site], entry)
			sitesByIP[id.ip] = append(sitesByIP[id.ip], id.site)
			if i, ok := index[id.site]; ok {
				view.Sites[i].ActiveIPs++
			}
		}
	}
	order := func(values []candidate) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].view.Requests != values[j].view.Requests {
				return values[i].view.Requests > values[j].view.Requests
			}
			return values[i].id.ip.Compare(values[j].id.ip) < 0
		})
	}
	decorate := func(item candidate) DashboardIP {
		result := item.view
		unique404 := make(map[string]struct{})
		result.PathSamples = topKeys(item.record.paths, 10)
		result.MissingPathSamples = topKeys(item.record.missing, 10)
		result.QueryPatterns = topKeys(item.record.queries, 10)
		result.UserAgents = topKeys(item.record.agents, 10)
		counts := make(map[string]uint64)
		for _, bucket := range item.record.buckets {
			if !bucket.used || bucket.second < cutoff || bucket.second > at.Unix() {
				continue
			}
			for agent, count := range bucket.uaCounts {
				counts[agent] += count
			}
			for path := range bucket.missing {
				unique404[path] = struct{}{}
			}
		}
		result.Unique404Paths = len(unique404)
		type agentCount struct {
			name  string
			count uint64
		}
		ordered := make([]agentCount, 0, len(counts))
		for name, count := range counts {
			ordered = append(ordered, agentCount{name, count})
		}
		sort.Slice(ordered, func(i, j int) bool {
			if ordered[i].count != ordered[j].count {
				return ordered[i].count > ordered[j].count
			}
			return ordered[i].name < ordered[j].name
		})
		if len(ordered) > 10 {
			ordered = ordered[:10]
		}
		result.UserAgentRequests = make(map[string]uint64, len(ordered))
		for _, agent := range ordered {
			result.UserAgentRequests[agent.name] = agent.count
		}
		return result
	}
	order(global)
	for i := 0; i < len(global) && i < limit; i++ {
		item := decorate(global[i])
		item.SiteIDs = sitesByIP[item.IP]
		sort.Strings(item.SiteIDs)
		view.TopIPs = append(view.TopIPs, item)
	}
	for site, items := range bySite {
		order(items)
		for i := 0; i < len(items) && i < limit; i++ {
			view.SiteIPs[site] = append(view.SiteIPs[site], decorate(items[i]))
		}
	}
	sort.Slice(view.Sites, func(i, j int) bool { return view.Sites[i].SiteID < view.Sites[j].SiteID })
	return view
}

func topKeys(values map[string]uint16, limit int) []string {
	result := make([]string, 0, min(len(values), limit))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}
