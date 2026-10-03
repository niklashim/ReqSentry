package dashboard

import (
	"github.com/niklashim/ReqSentry/internal/storage"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

func (s *Server) requestSampleAPI(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "incident history unavailable", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	limit, ok := boundedInt(q.Get("limit"), 50, 1, 50)
	if !ok {
		badQuery(w)
		return
	}
	page, ok := boundedInt(q.Get("page"), 1, 1, 201)
	if !ok {
		badQuery(w)
		return
	}
	status, ok := boundedInt(q.Get("status"), 0, 100, 599)
	if !ok {
		badQuery(w)
		return
	}
	to := time.Now()
	from := to.Add(-4 * 24 * time.Hour)
	for key, value := range map[string]*time.Time{"from": &from, "to": &to} {
		if q.Get(key) != "" {
			parsed, err := time.Parse(time.RFC3339, q.Get(key))
			if err != nil {
				badQuery(w)
				return
			}
			*value = parsed
		}
	}
	if to.Before(from) || to.Sub(from) > 366*24*time.Hour {
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
	var incidentID int64
	if q.Get("incident_id") != "" {
		id, err := strconv.ParseInt(q.Get("incident_id"), 10, 64)
		if err != nil || id < 1 {
			badQuery(w)
			return
		}
		incidentID = id
	}
	f := storage.RequestSampleFilter{From: from, To: to, Site: q.Get("site"), Server: q.Get("server"), IP: ip, Method: q.Get("method"), Status: status, Query: q.Get("q"), IncidentID: incidentID, Limit: limit, Offset: (page - 1) * limit}
	if len(f.Site) > 128 || len(f.Server) > 128 || len(f.Method) > 32 || len(f.Query) > 256 || f.Offset > 10000 {
		badQuery(w)
		return
	}
	items, total, err := s.store.SearchRequestSamples(r.Context(), f)
	if err != nil {
		http.Error(w, "incident request samples unavailable", http.StatusServiceUnavailable)
		return
	}
	var next *int
	if page < 201 && page*limit < total && (page*limit) <= 10000 {
		v := page + 1
		next = &v
	}
	jsonResponse(w, map[string]any{"samples": items, "total": total, "page": page, "limit": limit, "next_page": next, "coverage": "up to five saved request samples per incident; overlapping incidents can repeat requests; historical incidents may have no samples", "from": from, "to": to})
}
