package detector

import "github.com/niklashim/ReqSentry/internal/config"

func thresholds(rules config.DetectionConfig) map[string]float64 {
	values := config.DefaultDetectionConfig().Thresholds
	for key, value := range rules.Thresholds {
		values[key] = value
	}
	return values
}
