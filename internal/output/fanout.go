package output

import (
	"context"
	"errors"

	"github.com/niklashim/ReqSentry/internal/model"
)

// Fanout delivers to every sink even when an earlier destination fails.
type Fanout []model.IncidentSink

func (sinks Fanout) WriteIncident(ctx context.Context, incident model.Incident) error {
	var failures []error
	for _, sink := range sinks {
		if err := sink.WriteIncident(ctx, incident); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
