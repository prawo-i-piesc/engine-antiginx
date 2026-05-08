package strategyImpl

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type HeaderStrategyTest struct {
	Name            string
	wantErr         bool
	Ctx             strategy.TestContext
	expectedResults int
	antiBotFlag     bool
	getTest         func(testId string) (*Tests.ResponseTest, bool)
}

func setUp(t *testing.T) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		writer.WriteHeader(500)
	}))
	t.Cleanup(func() {
		defer server.Close()
	})
	return server
}

func TestHeaderTestHelp_Execute(t *testing.T) {
	server := setUp(t)
	tests := []HeaderStrategyTest{
		{
			Name:    "Happy path",
			wantErr: false,
			Ctx: strategy.TestContext{
				Target: server.URL,
				Args:   []string{"test", "test1"},
			},
			expectedResults: 2,
			antiBotFlag:     false,
			getTest: func(testId string) (*Tests.ResponseTest, bool) {
				return &Tests.ResponseTest{
					Id:          "test",
					Name:        "test",
					Description: "test",
					RunTest: func(params Tests.ResponseTestParams) Tests.TestResult {
						return Tests.TestResult{}
					},
				}, true
			},
		},
		{
			Name:    "Test does not exists",
			wantErr: true,
			Ctx: strategy.TestContext{
				Target: server.URL,
				Args:   []string{"nonExisting"},
			},
			expectedResults: 0,
			antiBotFlag:     false,
			getTest: func(testId string) (*Tests.ResponseTest, bool) {
				return nil, false
			},
		},
	}
	for _, val := range tests {
		t.Run(val.Name, func(t *testing.T) {
			channel := make(chan strategy.ResultWrapper, 10)
			wg := &sync.WaitGroup{}

			defer func() {
				r := recover()

				if !val.wantErr {
					if r != nil {
						t.Errorf("Unexpected panic in test %s, \n %v", val.Name, r)
					}
					return
				}

				if r == nil {
					t.Errorf("Expected panic but got none in test %s, \n %v", val.Name, r)
				}
			}()
			headerStrategy := InitializeHeaderStrategy(
				func(target string, useAntiBotDetection bool) (*http.Response, *strategy.RequestInfo) {
					return &http.Response{}, nil
				}, val.getTest,
				func(target string, params []string) *string {
					return &target
				},
			)
			headerStrategy.Execute(val.Ctx, channel, wg, val.antiBotFlag)
			wg.Wait()
			close(channel)

			var actualResults []strategy.ResultWrapper
			for res := range channel {
				actualResults = append(actualResults, res)
			}
			if len(actualResults) != val.expectedResults {
				t.Errorf("Expected %d results on channel, but got %d", val.expectedResults, len(actualResults))
			}
		})
	}
}
