package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// EnsureEventID identifies one ruleset's decision for a site/client/window.
// It excludes enrichment and error samples so later context does not rewrite history.
func (i *Incident) EnsureEventID() {
	if i.EventID != "" {
		return
	}
	codes := make([]string, 0, len(i.Signals))
	for _, s := range i.Signals {
		codes = append(codes, s.Code)
	}
	sort.Strings(codes)
	b, _ := json.Marshal([]any{i.Server, i.SiteID, i.ClientIP.String(), i.WindowStart, i.WindowEnd, i.RulesetVersion, codes})
	h := sha256.Sum256(b)
	i.EventID = hex.EncodeToString(h[:16])
}
