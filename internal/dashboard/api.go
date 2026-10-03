package dashboard

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
	"github.com/niklashim/ReqSentry/internal/watcher"
)

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > 2048 || len(r.URL.Path) > 512 {
		http.Error(w, "request too large", http.StatusRequestURITooLong)
		return
	}
	if s.source == nil {
		http.Error(w, "data unavailable", http.StatusServiceUnavailable)
		return
	}
	encodedParts := strings.Split(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/"), "/")
	parts := make([]string, 0, len(encodedParts))
	for _, encoded := range encodedParts {
		part, err := url.PathUnescape(encoded)
		if err != nil || part == "." || part == ".." {
			badQuery(w)
			return
		}
		parts = append(parts, part)
	}
	if len(parts) == 0 || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	maxLimit := 50
	if parts[0] == "incidents" {
		maxLimit = 100
	}
	limit, ok := boundedInt(q.Get("limit"), 20, 1, maxLimit)
	if !ok {
		badQuery(w)
		return
	}
	window, label, ok := selectedRange(q.Get("range"))
	if !ok {
		badQuery(w)
		return
	}
	// Incident and health routes do not need a rolling IP scan. Build the
	// bounded dashboard view only for routes that actually return it.
	var view aggregator.DashboardView
	viewReady := false
	getView := func() aggregator.DashboardView {
		if !viewReady {
			view = s.source.Dashboard(min(window, time.Minute), limit)
			viewReady = true
		}
		return view
	}
	switch parts[0] {
	case "request-samples":
		if len(parts) != 1 {
			break
		}
		s.requestSampleAPI(w, r)
		return
	case "errors":
		if len(parts) != 1 {
			break
		}
		from, to := time.Now().Add(-window), time.Now()
		if len(q.Get("site")) > 128 || len(q.Get("severity")) > 16 || len(q.Get("category")) > 128 {
			badQuery(w)
			return
		}
		events := []model.ErrorEvent{}
		if s.store != nil {
			var err error
			events, err = s.store.RecentErrors(r.Context(), q.Get("site"), q.Get("severity"), q.Get("category"), from, to, limit)
			if err != nil {
				http.Error(w, "error history unavailable", http.StatusServiceUnavailable)
				return
			}
		} else if src, ok := s.source.(interface {
			RecentErrors(string, time.Time, time.Time, int) []model.ErrorEvent
		}); ok {
			events = src.RecentErrors(q.Get("site"), from, to, limit)
			filtered := events[:0]
			for _, e := range events {
				if (q.Get("severity") == "" || e.Severity == q.Get("severity")) && (q.Get("category") == "" || e.Category == q.Get("category")) {
					filtered = append(filtered, e)
				}
			}
			events = filtered
		}
		sources := []watcher.Status{}
		if src, ok := s.source.(interface{ ErrorSources() []watcher.Status }); ok {
			sources = src.ErrorSources()
		}
		coverage := "bounded persisted samples; queued or dropped events may be absent"
		if s.store == nil {
			coverage = "bounded live samples; history unavailable"
		}
		if len(sources) == 0 {
			coverage = "no error source configured"
		}
		association := q.Get("association")
		related := []int64{}
		if association != "" {
			allowed := false
			for _, v := range []string{"request_id", "trace_id", "logged_client_path_time", "site_time", "server_time"} {
				if association == v {
					allowed = true
				}
			}
			if !allowed {
				badQuery(w)
				return
			}
			events = []model.ErrorEvent{}
			coverage = "bounded saved incident correlation samples; association does not establish causation"
			if s.store != nil {
				items, _, err := s.store.SearchIncidents(r.Context(), storage.IncidentFilter{From: from, To: to, Site: q.Get("site"), MinScore: 0, MaxScore: 100, Limit: 50})
				if err != nil {
					http.Error(w, "correlation history unavailable", http.StatusServiceUnavailable)
					return
				}
				// Fingerprints group failures; they are not event identities. Keep
				// separate requests even when their timestamp and message match.
				seen := map[model.ErrorEvent]bool{}
				for _, item := range items {
					if item.Incident.Errors == nil {
						continue
					}
					matched := false
					for _, sample := range item.Incident.Errors.Samples {
						event := sample.Event
						if event.Timestamp.Before(from) || event.Timestamp.After(to) || sample.Method != association || (q.Get("severity") != "" && event.Severity != q.Get("severity")) || (q.Get("category") != "" && event.Category != q.Get("category")) {
							continue
						}
						matched = true
						if !seen[event] && len(events) < limit {
							events = append(events, event)
							seen[event] = true
						}
					}
					if matched {
						related = append(related, item.ID)
					}
				}
			}
		}
		step := max(int64(60), int64(window.Seconds())/120+1)
		timeline := []storage.ErrorBucket{}
		if s.store != nil && association == "" {
			if buckets, err := s.store.ErrorHistory(r.Context(), q.Get("site"), from, to, step); err == nil {
				timeline = buckets
			}
		}
		jsonResponse(w, map[string]any{"errors": events, "timeline": timeline, "bucket_seconds": step, "sources": sources, "coverage": coverage, "range": label, "related_incidents": related})
		return
	case "server":
		if len(parts) != 1 {
			break
		}
		health, available := s.source.Health()
		jsonResponse(w, map[string]any{"name": s.source.ServerName(), "monitor_only": true, "health": health, "health_available": available, "php_fpm": s.source.PHPFPM(), "analysis_active": s.source.DeepAnalysisActive(), "recent_incident_summary": summarizeIncidents(s.source.Incidents(), time.Now())})
		return
	case "stats":
		if len(parts) != 1 {
			break
		}
		data := map[string]any{"range": label, "live": getView(), "coverage": "server and site totals are exact within the in-memory window; IP, path, user-agent and ASN lists are bounded tracked samples"}
		if window > time.Minute {
			if s.store == nil {
				data["history_available"] = false
			} else {
				history, err := s.history(r.Context(), q.Get("site"), window)
				if err != nil {
					http.Error(w, "history unavailable", http.StatusServiceUnavailable)
					return
				}
				data["history_available"] = true
				data["history"] = history
			}
		}
		jsonResponse(w, data)
		return
	case "sites":
		if len(parts) == 1 {
			current := getView()
			jsonResponse(w, map[string]any{"at": current.At, "window_seconds": current.WindowSeconds, "sites": current.Sites})
			return
		}
		site := parts[1]
		if site == "" || len(site) > 128 {
			badQuery(w)
			return
		}
		for _, item := range getView().Sites {
			if item.SiteID == site {
				tracked := getView().SiteIPs[site]
				data := map[string]any{"site": item, "top_ips": tracked, "top_networks": s.networksFor(tracked), "samples": summarizeSamples(tracked), "sample_coverage": "top tracked IPs only; path, query and user-agent counts are numbers of tracked IPs with the sample, not request totals"}
				if s.store != nil && window > time.Minute {
					history, err := s.history(r.Context(), site, window)
					if err != nil {
						http.Error(w, "history unavailable", http.StatusServiceUnavailable)
						return
					}
					data["history"] = history
				}
				if s.store != nil {
					ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
					defer cancel()
					items, total, err := s.store.SearchIncidents(ctx, storage.IncidentFilter{From: time.Now().Add(-24 * time.Hour), To: time.Now(), Site: site, MinScore: 0, MaxScore: 100, Limit: 10})
					if err == nil {
						data["recent_incidents"] = items
						data["incident_count_24h"] = total
					}
				}
				jsonResponse(w, data)
				return
			}
		}
		http.NotFound(w, r)
		return
	case "ips":
		if len(parts) == 1 {
			items := getView().TopIPs
			if site := q.Get("site"); site != "" {
				items = getView().SiteIPs[site]
			}
			jsonResponse(w, map[string]any{"ips": items, "sample_coverage": "top tracked IPs only", "window_seconds": getView().WindowSeconds})
			return
		}
		ip, err := netip.ParseAddr(parts[1])
		if err != nil {
			badQuery(w)
			return
		}
		ip = ip.Unmap()
		snapshot, found := s.source.IPSnapshot(q.Get("site"), ip, min(window, time.Minute))
		if !found {
			http.NotFound(w, r)
			return
		}
		enrich, enrichErr := s.source.Enrich(ip)
		data := map[string]any{"snapshot": snapshot, "enrichment": enrich, "enrichment_available": enrichErr == nil && enrich.Available, "window_seconds": int(min(window, time.Minute) / time.Second)}
		if s.store != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			items, total, err := s.store.SearchIncidents(ctx, storage.IncidentFilter{From: time.Now().Add(-7 * 24 * time.Hour), To: time.Now(), IP: ip.String(), MinScore: 0, MaxScore: 100, Limit: 20})
			if err == nil {
				data["recent_incidents"] = items
				data["incident_count_7d"] = total
			}
		}
		jsonResponse(w, data)
		return
	case "asns":
		if len(parts) > 2 {
			break
		}
		networks := s.networks(getView())
		if len(parts) == 1 {
			jsonResponse(w, map[string]any{"networks": networks, "sample_coverage": "top tracked IPs with available local MaxMind enrichment"})
			return
		}
		asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(parts[1]), "AS"), 10, 32)
		if err != nil || asn == 0 {
			badQuery(w)
			return
		}
		for _, item := range networks {
			if item.ASN == uint32(asn) {
				jsonResponse(w, item)
				return
			}
		}
		http.NotFound(w, r)
		return
	case "phpfpm":
		if len(parts) != 1 {
			break
		}
		jsonResponse(w, map[string]any{"pools": s.source.PHPFPM()})
		return
	case "user-agents":
		if len(parts) != 1 {
			break
		}
		counts := map[string]struct {
			Requests            uint64 `json:"sampled_requests"`
			UniqueIPs           int    `json:"tracked_ips"`
			RecentSuspiciousIPs int    `json:"recent_suspicious_ips"`
			RecentWouldBlockIPs int    `json:"recent_would_block_ips"`
		}{}
		recentDecisions := map[netip.Addr]model.Decision{}
		cutoff := time.Now().Add(-5 * time.Minute)
		for _, incident := range s.source.Incidents() {
			if incident.Timestamp.Before(cutoff) {
				continue
			}
			if incident.Decision == model.DecisionWouldBlock {
				recentDecisions[incident.ClientIP.Unmap()] = model.DecisionWouldBlock
			} else if incident.Decision == model.DecisionSuspicious && recentDecisions[incident.ClientIP.Unmap()] != model.DecisionWouldBlock {
				recentDecisions[incident.ClientIP.Unmap()] = model.DecisionSuspicious
			}
		}
		var missing uint64
		for _, item := range getView().TopIPs {
			missing += item.MissingUserAgent
			for agent, requests := range item.UserAgentRequests {
				value := counts[agent]
				value.Requests += requests
				value.UniqueIPs++
				if recentDecisions[item.IP] == model.DecisionSuspicious || recentDecisions[item.IP] == model.DecisionWouldBlock {
					value.RecentSuspiciousIPs++
				}
				if recentDecisions[item.IP] == model.DecisionWouldBlock {
					value.RecentWouldBlockIPs++
				}
				counts[agent] = value
			}
		}
		jsonResponse(w, map[string]any{"agents": counts, "sampled_missing_user_agent_requests": missing, "sample_coverage": "request counts and unique IPs among top tracked IPs only; recent suspicious counts associate IPs with User-Agent samples but do not attribute a decision to a particular User-Agent"})
		return
	case "incidents":
		s.incidentAPI(w, r, parts)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) history(ctx context.Context, site string, window time.Duration) ([]storage.HistorySample, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	now := time.Now()
	return s.store.DashboardHistory(queryCtx, site, now.Add(-window), now, 500)
}

type networkView struct {
	ASN                 uint32                   `json:"asn"`
	Organization        string                   `json:"organization"`
	NetworkType         string                   `json:"network_type"`
	Country             string                   `json:"country"`
	TrackedIPs          int                      `json:"tracked_ips"`
	SampledRequests     uint64                   `json:"sampled_requests"`
	Sampled404          uint64                   `json:"sampled_404"`
	IPs                 []aggregator.DashboardIP `json:"ips"`
	RecentIncidentCount int                      `json:"recent_incident_count"`
	RecentSuspiciousIPs int                      `json:"recent_suspicious_ips"`
	RecentWouldBlockIPs int                      `json:"recent_would_block_ips"`
	RecentSites         []string                 `json:"recent_sites"`
}

func (s *Server) networks(view aggregator.DashboardView) []networkView {
	return s.networksFor(view.TopIPs)
}

func (s *Server) networksFor(ips []aggregator.DashboardIP) []networkView {
	byASN := map[uint32]*networkView{}
	for _, item := range ips {
		result, err := s.source.Enrich(item.IP)
		if err != nil || result.ASN == nil {
			continue
		}
		network := byASN[*result.ASN]
		if network == nil {
			network = &networkView{ASN: *result.ASN, Organization: result.ASNOrganization, NetworkType: result.NetworkType, Country: result.Country}
			byASN[*result.ASN] = network
		}
		network.TrackedIPs++
		network.SampledRequests += item.Requests
		network.Sampled404 += item.NotFound
		network.IPs = append(network.IPs, item)
	}
	values := make([]networkView, 0, len(byASN))
	recent := s.source.Incidents()
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, value := range byASN {
		seenSuspicious := map[netip.Addr]bool{}
		seenWouldBlock := map[netip.Addr]bool{}
		sites := map[string]bool{}
		for _, incident := range recent {
			if incident.ASN == nil || *incident.ASN != value.ASN || incident.Timestamp.Before(cutoff) {
				continue
			}
			value.RecentIncidentCount++
			if incident.Decision == model.DecisionSuspicious || incident.Decision == model.DecisionWouldBlock {
				seenSuspicious[incident.ClientIP] = true
			}
			if incident.Decision == model.DecisionWouldBlock {
				seenWouldBlock[incident.ClientIP] = true
			}
			if incident.SiteID != "" {
				sites[incident.SiteID] = true
			}
		}
		value.RecentSuspiciousIPs = len(seenSuspicious)
		value.RecentWouldBlockIPs = len(seenWouldBlock)
		for site := range sites {
			value.RecentSites = append(value.RecentSites, site)
		}
		sort.Strings(value.RecentSites)
		values = append(values, *value)
	}
	sortNetworks(values)
	return values
}

type sampleCounts struct {
	Paths         map[string]int `json:"paths"`
	MissingPaths  map[string]int `json:"missing_paths"`
	QueryPatterns map[string]int `json:"query_patterns"`
	UserAgents    map[string]int `json:"user_agents"`
}

func summarizeSamples(items []aggregator.DashboardIP) sampleCounts {
	result := sampleCounts{Paths: map[string]int{}, MissingPaths: map[string]int{}, QueryPatterns: map[string]int{}, UserAgents: map[string]int{}}
	for _, item := range items {
		for _, value := range item.PathSamples {
			result.Paths[value]++
		}
		for _, value := range item.MissingPathSamples {
			result.MissingPaths[value]++
		}
		for _, value := range item.QueryPatterns {
			result.QueryPatterns[value]++
		}
		for _, value := range item.UserAgents {
			result.UserAgents[value]++
		}
	}
	return result
}

func (s *Server) incidentAPI(w http.ResponseWriter, r *http.Request, parts []string) {
	if s.store == nil {
		http.Error(w, "incident history unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if len(parts) == 2 {
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || id < 1 {
			badQuery(w)
			return
		}
		item, found, err := s.store.IncidentByID(ctx, id)
		if err != nil {
			http.Error(w, "incident unavailable", http.StatusServiceUnavailable)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		jsonResponse(w, item)
		return
	}
	q := r.URL.Query()
	limit, ok := boundedInt(q.Get("limit"), 20, 1, 100)
	if !ok {
		badQuery(w)
		return
	}
	page, ok := boundedInt(q.Get("page"), 1, 1, 10001)
	if !ok {
		badQuery(w)
		return
	}
	minScore, ok := boundedInt(q.Get("min_score"), 0, 0, 100)
	if !ok {
		badQuery(w)
		return
	}
	maxScore, ok := boundedInt(q.Get("max_score"), 100, 0, 100)
	if !ok || minScore > maxScore {
		badQuery(w)
		return
	}
	to := time.Now()
	from := to.Add(-24 * time.Hour)
	if q.Get("from") != "" {
		var err error
		from, err = time.Parse(time.RFC3339, q.Get("from"))
		if err != nil {
			badQuery(w)
			return
		}
	}
	if q.Get("to") != "" {
		var err error
		to, err = time.Parse(time.RFC3339, q.Get("to"))
		if err != nil {
			badQuery(w)
			return
		}
	}
	if to.Before(from) || to.Sub(from) > 366*24*time.Hour {
		badQuery(w)
		return
	}
	decision := model.Decision(q.Get("decision"))
	switch decision {
	case "", model.DecisionNormal, model.DecisionWatch, model.DecisionSuspicious, model.DecisionWouldBlock:
	default:
		badQuery(w)
		return
	}
	ip := q.Get("ip")
	if ip != "" {
		parsed, err := netip.ParseAddr(ip)
		if err != nil {
			badQuery(w)
			return
		}
		ip = parsed.Unmap().String()
	}
	filter := storage.IncidentFilter{From: from, To: to, Site: q.Get("site"), IP: ip, Decision: decision, MinScore: minScore, MaxScore: maxScore, Signal: q.Get("signal"), Server: q.Get("server"), Query: q.Get("q"), Limit: limit, Offset: (page - 1) * limit}
	if len(filter.Site) > 128 || len(filter.Signal) > 128 || len(filter.Server) > 128 || len(filter.Query) > 256 || filter.Offset > 10000 {
		badQuery(w)
		return
	}
	items, total, err := s.store.SearchIncidents(ctx, filter)
	if err != nil {
		http.Error(w, "incident history unavailable", http.StatusServiceUnavailable)
		return
	}
	var nextPage *int
	if page*limit < total && page*limit <= 10000 {
		value := page + 1
		nextPage = &value
	}
	jsonResponse(w, map[string]any{"incidents": items, "total": total, "page": page, "limit": limit, "next_page": nextPage})
}

func badQuery(w http.ResponseWriter) { http.Error(w, "invalid query", http.StatusBadRequest) }

func boundedInt(value string, fallback, minimum, maximum int) (int, bool) {
	if value == "" {
		return fallback, true
	}
	n, err := strconv.Atoi(value)
	return n, err == nil && n >= minimum && n <= maximum
}

func selectedRange(value string) (time.Duration, string, bool) {
	if value == "" {
		value = "1m"
	}
	switch value {
	case "1m":
		return time.Minute, value, true
	case "5m":
		return 5 * time.Minute, value, true
	case "15m":
		return 15 * time.Minute, value, true
	case "1h":
		return time.Hour, value, true
	case "6h":
		return 6 * time.Hour, value, true
	case "24h":
		return 24 * time.Hour, value, true
	case "7d":
		return 7 * 24 * time.Hour, value, true
	default:
		return 0, "", false
	}
}

func sortNetworks(values []networkView) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].SampledRequests != values[j].SampledRequests {
			return values[i].SampledRequests > values[j].SampledRequests
		}
		return values[i].ASN < values[j].ASN
	})
}

type incidentSummary struct {
	ActiveIncidents int    `json:"active_incidents"`
	SuspiciousIPs   int    `json:"suspicious_ips"`
	WouldBlockIPs   int    `json:"would_block_ips"`
	Coverage        string `json:"coverage"`
}

func summarizeIncidents(items []model.Incident, now time.Time) incidentSummary {
	result := incidentSummary{Coverage: "last five minutes of at most 100 in-memory incidents"}
	suspicious := map[netip.Addr]bool{}
	wouldBlock := map[netip.Addr]bool{}
	for _, item := range items {
		if item.Timestamp.Before(now.Add(-5*time.Minute)) || item.Timestamp.After(now) {
			continue
		}
		result.ActiveIncidents++
		if item.Decision == model.DecisionSuspicious || item.Decision == model.DecisionWouldBlock {
			suspicious[item.ClientIP] = true
		}
		if item.Decision == model.DecisionWouldBlock {
			wouldBlock[item.ClientIP] = true
		}
	}
	result.SuspiciousIPs = len(suspicious)
	result.WouldBlockIPs = len(wouldBlock)
	return result
}
