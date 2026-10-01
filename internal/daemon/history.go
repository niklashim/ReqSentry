package daemon

import (
	"context"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/storage"
)

func (d *Daemon) monitorDashboardHistory(ctx context.Context, rollup *aggregator.Aggregator) {
	next := time.Now().Truncate(time.Minute).Add(time.Minute)
	for {
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			d.persistDashboardMinute(rollup, time.Now(), false)
			return
		case <-timer.C:
			d.persistDashboardMinute(rollup, next.Add(-time.Nanosecond), true)
			next = next.Add(time.Minute)
			if time.Now().After(next) {
				next = time.Now().Truncate(time.Minute).Add(time.Minute)
			}
		}
	}
}

func (d *Daemon) persistDashboardMinute(rollup *aggregator.Aggregator, at time.Time, complete bool) {
	if d.checkpointStore == nil {
		return
	}
	minute := at.UTC().Truncate(time.Minute)
	window := 60 * time.Second
	if !complete {
		window = time.Duration(at.Second()+1) * time.Second
	}
	view := rollup.Dashboard(window, at, 1)
	server := storage.HistorySample{At: minute, Requests: view.Requests, TrackedUniqueIPs: view.ActiveIPs, Status2xx: view.StatusFamilies[2], Status301: view.Statuses[301], Status302: view.Statuses[302], Status403: view.Statuses[403], Status404: view.Statuses[404], Status5xx: view.StatusFamilies[5], Complete: complete}
	health, _ := d.Health()
	server.CPUPercent = health.CPUPercent
	server.Load1 = health.Load1
	server.MemoryUsedPercent = health.MemoryUsedPercent
	var active, idle, queue int64
	phpAvailable := false
	for _, pool := range d.PHPFPM() {
		if pool.Stale || pool.Stats == nil {
			continue
		}
		if pool.Stats.ActiveProcesses != nil {
			active += *pool.Stats.ActiveProcesses
			phpAvailable = true
		}
		if pool.Stats.IdleProcesses != nil {
			idle += *pool.Stats.IdleProcesses
		}
		if pool.Stats.ListenQueue != nil {
			queue += *pool.Stats.ListenQueue
		}
	}
	if phpAvailable {
		server.PHPActive = &active
		server.PHPIdle = &idle
		server.PHPListenQueue = &queue
	}
	samples := []storage.HistorySample{server}
	for _, site := range view.Sites {
		item := storage.HistorySample{At: minute, SiteID: site.SiteID, Requests: site.Requests, TrackedUniqueIPs: site.ActiveIPs, Status2xx: site.StatusFamilies[2], Status301: site.Statuses[301], Status302: site.Statuses[302], Status403: site.Statuses[403], Status404: site.Statuses[404], Status5xx: site.StatusFamilies[5], Complete: complete}
		samples = append(samples, item)
	}
	countCtx, stopCount := context.WithTimeout(context.Background(), 2*time.Second)
	if err := d.checkpointStore.Flush(countCtx); err == nil {
		if total, perSite, err := d.checkpointStore.IncidentMinuteCounts(countCtx, minute); err == nil {
			samples[0].Incidents = &total.Incidents
			samples[0].WouldBlock = &total.WouldBlock
			for i := 1; i < len(samples); i++ {
				counts := perSite[samples[i].SiteID]
				samples[i].Incidents = &counts.Incidents
				samples[i].WouldBlock = &counts.WouldBlock
			}
		} else {
			d.logger.Printf("dashboard incident counts unavailable: %v", err)
		}
	} else {
		d.logger.Printf("dashboard incident counts unavailable: %v", err)
	}
	stopCount()
	writeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.checkpointStore.SaveDashboardMinutes(writeCtx, samples); err != nil {
		d.logger.Printf("dashboard history sample failed: %v", err)
	}
}
