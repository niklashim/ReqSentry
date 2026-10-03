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

// Retain five samples per bounded epoch across the counter retention horizon.
// Recovery may evaluate a closed epoch after newer epochs have arrived.
func (r *record) sample(request model.RequestSample, at time.Time, seconds int64) {
	epoch := sampleEpochAt(at, seconds)
	if epoch < sampleEpochAt(time.Unix(r.lastSeen, 0), seconds)-int64(len(r.samples))+1 {
		return
	}
	count := int64(len(r.samples))
	b := &r.samples[(epoch%count+count)%count]
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

// Match replay and live analysis's time.Truncate boundaries. Unix division
// alone disagrees for windows such as 31 seconds because Go truncates relative
// to year one, rather than the Unix epoch.
func sampleEpochAt(at time.Time, seconds int64) int64 {
	boundary := at.Truncate(time.Duration(seconds) * time.Second).Unix()
	epoch := boundary / seconds
	if boundary%seconds < 0 {
		epoch--
	}
	return epoch
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
