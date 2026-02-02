package Reporter

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type backendReporterTest struct {
	name            string
	statusCode      int
	expectedFailure int
	expectedCalls   int
}

func TestBackendReporter_StartListening(t *testing.T) {
	tests := []backendReporterTest{
		{
			name:            "Happy path,success on first try",
			statusCode:      http.StatusOK,
			expectedFailure: 0,
			expectedCalls:   2,
		},
		{
			name:            "Error 500, retryable",
			statusCode:      http.StatusInternalServerError,
			expectedFailure: 1,
			expectedCalls:   3,
		},
		{
			name:            "Error 400, non retryable",
			statusCode:      http.StatusBadRequest,
			expectedFailure: 1,
			expectedCalls:   1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				bodyBytes, _ := io.ReadAll(request.Body)
				fmt.Printf("Performed req %v\n", string(bodyBytes))
				writer.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			resChan := make(chan Tests.TestResult)

			reporter := InitializeBackendReporter(resChan, server.URL, "test-id", "target", 0, 0)

			done := reporter.StartListening()
			resChan <- Tests.TestResult{
				Name:        "Test scan",
				Certainty:   0,
				ThreatLevel: 0,
				Metadata:    nil,
				Description: "",
			}
			close(resChan)
			failedUploads := <-done

			if calls != tt.expectedCalls {
				t.Errorf("Expected calls %d, Calls made %d", tt.expectedCalls, calls)
			}

			if failedUploads != tt.expectedFailure {
				t.Errorf("Expected failures %d, Failures %d", tt.expectedFailure, failedUploads)
			}
		})
	}
}
