package Metrics

const (
	scanDurationMetric   = "engine_scan_duration_seconds"
	testDurationMetric   = "engine_test_duration_seconds"
	totalScans           = "engine_scan_outcomes_total"
	vulnerabilitiesTotal = "engine_vulnerabilities_found_total"
)

var outChan chan<- MetricsEvent

func SetChannel(ch chan<- MetricsEvent) {
	outChan = ch
}

func IncTotalScans(status string) {
	if outChan == nil {
		return
	}
	select {
	case outChan <- MetricsEvent{
		Name:   totalScans,
		Type:   Counter,
		Labels: []string{status},
		Value:  1,
	}:
	default:
	}
}

func IncVulnerabilitiesTotal(threatLevel string, testName string, value float64) {
	if outChan == nil {
		return
	}

	select {
	case outChan <- MetricsEvent{
		Name:   vulnerabilitiesTotal,
		Type:   Counter,
		Labels: []string{threatLevel, testName},
		Value:  value,
	}:
	default:
	}
}

func ObserveScanDurationTime(value float64) {
	if outChan == nil {
		return
	}

	select {
	case outChan <- MetricsEvent{
		Name:   scanDurationMetric,
		Type:   Histogram,
		Labels: []string{},
		Value:  value,
	}:
	default:
	}
}

func ObserveTestDurationTime(testName string, value float64) {
	if outChan == nil {
		return
	}

	select {
	case outChan <- MetricsEvent{
		Name:   testDurationMetric,
		Type:   Histogram,
		Labels: []string{testName},
		Value:  value,
	}:
	default:
	}
}

type MetricType int

const (
	Histogram MetricType = iota
	Counter
	Gauge
)

type MetricsEvent struct {
	Name   string
	Type   MetricType
	Labels []string
	Value  float64
}
