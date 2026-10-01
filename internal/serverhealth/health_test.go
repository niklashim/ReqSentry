package serverhealth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
)

func writeProc(t *testing.T, dir, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProcSamplerUsesCounterDeltasAndKeepsPartialMeasurements(t *testing.T) {
	dir := t.TempDir()
	writeProc(t, dir, "stat", "cpu 100 0 50 850 0 0 0 0 0 0\n")
	writeProc(t, dir, "loadavg", "1.25 2.50 3.75 2/100 123\n")
	writeProc(t, dir, "meminfo", "MemTotal: 1000 kB\nMemAvailable: 400 kB\n")
	sampler := NewProcSampler(dir)
	first, err := sampler.Sample(time.Unix(100, 0))
	if err != nil || first.CPUPercent != nil || first.Load1 == nil || *first.Load1 != 1.25 || first.MemoryUsedPercent == nil || *first.MemoryUsedPercent != 60 {
		t.Fatalf("first sample: %+v error=%v", first, err)
	}
	writeProc(t, dir, "stat", "cpu 120 0 80 900 0 0 0 0 0 0\n")
	second, err := sampler.Sample(time.Unix(101, 0))
	if err != nil || second.CPUPercent == nil || *second.CPUPercent != 50 {
		t.Fatalf("second sample: %+v error=%v", second, err)
	}
	if err := os.Remove(filepath.Join(dir, "meminfo")); err != nil {
		t.Fatal(err)
	}
	third, err := sampler.Sample(time.Unix(102, 0))
	if err == nil || third.Load1 == nil || third.MemoryUsedPercent != nil {
		t.Fatalf("partial sample: %+v error=%v", third, err)
	}
}

func TestCPUTriggerHysteresisAndMissingSamples(t *testing.T) {
	cfg := config.TriggerConfig{
		Mode: "cpu", CPUStart: 80, CPUStop: 60,
		StartDuration: config.Duration{Duration: 10 * time.Second},
		StopDuration:  config.Duration{Duration: 60 * time.Second},
	}
	trigger := NewTrigger(cfg)
	base := time.Unix(1000, 0)
	high, low := 81.0, 59.0
	if active, changed := trigger.Update(base, &high); active || changed {
		t.Fatal("trigger started too early")
	}
	if active, changed := trigger.Update(base.Add(9*time.Second), &high); active || changed {
		t.Fatal("trigger started before duration")
	}
	if active, changed := trigger.Update(base.Add(10*time.Second), &high); !active || !changed {
		t.Fatal("trigger did not start after sustained high CPU")
	}
	trigger.Update(base.Add(11*time.Second), &low)
	if active, changed := trigger.Update(base.Add(70*time.Second), &low); !active || changed {
		t.Fatal("trigger stopped before low duration")
	}
	if active, changed := trigger.Update(base.Add(71*time.Second), &low); active || !changed {
		t.Fatal("trigger did not stop after sustained low CPU")
	}
	trigger.Update(base.Add(72*time.Second), &high)
	trigger.Update(base.Add(80*time.Second), nil)
	if active, changed := trigger.Update(base.Add(81*time.Second), &high); active || changed {
		t.Fatal("missing CPU sample did not reset high streak")
	}
	if !NewTrigger(config.TriggerConfig{Mode: "always"}).Active() {
		t.Fatal("always mode must start active")
	}
}
