package aggregator

import (
	"github.com/niklashim/ReqSentry/internal/model"
	"sort"
	"time"
)

type timedSample struct {
	at      time.Time
	request model.RequestSample
}
type sampleEpoch struct {
	epoch  int64
	values []timedSample
}

// Two analysis epochs keep at most ten small samples per tracked identity.
// Keeping the preceding epoch also protects closed-window crash recovery from
// new requests arriving immediately after its boundary.
func (r *record) sample(request model.RequestSample, at time.Time, seconds int64) {
	epoch := at.Unix() / seconds
	if epoch < r.lastSeen/seconds-1 {
		return
	}
	b := &r.samples[(epoch%2+2)%2]
	if b.values == nil || b.epoch != epoch {
		*b = sampleEpoch{epoch: epoch, values: make([]timedSample, 0, model.MaxRequestSamples)}
	}
	if len(b.values) == model.MaxRequestSamples && at.Before(b.values[0].at) {
		return
	}
	value := timedSample{at: at, request: request}
	if value.request.Timestamp.IsZero() {
		value.request.Timestamp = at
	}
	if len(b.values) == model.MaxRequestSamples {
		copy(b.values, b.values[1:])
		b.values[len(b.values)-1] = value
	} else {
		b.values = append(b.values, value)
	}
	for i := len(b.values) - 1; i > 0 && b.values[i].at.Before(b.values[i-1].at); i-- {
		b.values[i], b.values[i-1] = b.values[i-1], b.values[i]
	}
}

func (r *record) requestSamples(cutoff int64, at time.Time) []model.RequestSample {
	values := make([]timedSample, 0, 2*model.MaxRequestSamples)
	for _, b := range r.samples {
		for _, v := range b.values {
			if v.at.Unix() >= cutoff && !v.at.After(at) {
				values = append(values, v)
			}
		}
	}
	sort.SliceStable(values, func(i, j int) bool { return values[i].at.Before(values[j].at) })
	if len(values) > model.MaxRequestSamples {
		values = values[len(values)-model.MaxRequestSamples:]
	}
	out := make([]model.RequestSample, 0, len(values))
	for _, v := range values {
		s := v.request
		if s.Bytes != nil {
			b := *s.Bytes
			s.Bytes = &b
		}
		if s.RequestMS != nil {
			ms := *s.RequestMS
			s.RequestMS = &ms
		}
		out = append(out, s)
	}
	return out
}
