package Metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetrics_NilChannel(t *testing.T) {
	SetChannel(nil)

	IncTotalScans("success")
	IncVulnerabilitiesTotal("High", "xss", 1.0)
	ObserveScanDurationTime(1.5)
	ObserveTestDurationTime("csp", 0.5)
}

func TestMetrics_SendEvents(t *testing.T) {
	ch := make(chan MetricsEvent, 4)
	SetChannel(ch)
	defer SetChannel(nil)

	IncTotalScans("success")
	event := <-ch
	assert.Equal(t, totalScans, event.Name)
	assert.Equal(t, Counter, event.Type)
	assert.Equal(t, []string{"success"}, event.Labels)
	assert.Equal(t, 1.0, event.Value)

	IncVulnerabilitiesTotal("Critical", "sqli", 2.0)
	event = <-ch
	assert.Equal(t, vulnerabilitiesTotal, event.Name)
	assert.Equal(t, Counter, event.Type)
	assert.Equal(t, []string{"Critical", "sqli"}, event.Labels)
	assert.Equal(t, 2.0, event.Value)

	ObserveScanDurationTime(10.5)
	event = <-ch
	assert.Equal(t, scanDurationMetric, event.Name)
	assert.Equal(t, Histogram, event.Type)
	assert.Empty(t, event.Labels)
	assert.Equal(t, 10.5, event.Value)

	ObserveTestDurationTime("csp_test", 1.2)
	event = <-ch
	assert.Equal(t, testDurationMetric, event.Name)
	assert.Equal(t, Histogram, event.Type)
	assert.Equal(t, []string{"csp_test"}, event.Labels)
	assert.Equal(t, 1.2, event.Value)
}

func TestMetrics_ChannelFull_DoesNotBlock(t *testing.T) {
	ch := make(chan MetricsEvent, 1)
	SetChannel(ch)
	defer SetChannel(nil)

	ch <- MetricsEvent{Name: "filler_event"}

	IncTotalScans("failed")

	event := <-ch
	assert.Equal(t, "filler_event", event.Name)
}
