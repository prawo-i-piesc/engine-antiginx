package strategyImpl

import (
	"Engine-AntiGinx/App/Tests"
	"Engine-AntiGinx/App/execution/strategy"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
)

type HeaderStrategyTest struct {
	Name            string
	wantErr         bool
	Ctx             strategy.TestContext
	expectedResults int
	antiBotFlag     bool
	getTest         func(testId string) (Tests.Test, bool)
	loadContent     strategy.ContentLoader
	wantLoadCalls   int32
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

// stubTest builds a test of the requested kind that reports nothing, so assertions can
// count results without depending on any real analysis.
func stubTest(id string, kind Tests.TestKind) Tests.Test {
	switch kind {
	case Tests.PreResponse:
		return &Tests.PreResponseTest{
			Id: id, Name: id, Description: id,
			RunTest: func(params Tests.PreResponseTestParams) Tests.TestResult {
				return Tests.TestResult{Name: id}
			},
		}
	case Tests.Structure:
		return &Tests.StructureTest{
			Id: id, Name: id, Description: id,
			RunTest: func(params Tests.StructureTestParams) Tests.TestResult {
				return Tests.TestResult{Name: id}
			},
		}
	default:
		return &Tests.ResponseTest{
			Id: id, Name: id, Description: id,
			RunTest: func(params Tests.ResponseTestParams) Tests.TestResult {
				return Tests.TestResult{Name: id}
			},
		}
	}
}

// byKind resolves a test id to a stub of the kind registered for it.
func byKind(kinds map[string]Tests.TestKind) func(string) (Tests.Test, bool) {
	return func(testId string) (Tests.Test, bool) {
		kind, ok := kinds[testId]
		if !ok {
			return nil, false
		}
		return stubTest(testId, kind), true
	}
}

func TestHeaderTestHelp_Execute(t *testing.T) {
	server := setUp(t)

	okLoader := func(target string, useAntiBotDetection bool) (*http.Response, *strategy.RequestInfo) {
		return &http.Response{}, &strategy.RequestInfo{}
	}
	// A blocked main request: the Response phase has nothing to analyze, everything else does.
	blockedLoader := func(target string, useAntiBotDetection bool) (*http.Response, *strategy.RequestInfo) {
		return nil, &strategy.RequestInfo{
			Message: "Bot protection detected",
			Code:    300,
		}
	}

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
			getTest:         byKind(map[string]Tests.TestKind{"test": Tests.Response, "test1": Tests.Response}),
			loadContent:     okLoader,
			wantLoadCalls:   1,
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
			getTest:         byKind(map[string]Tests.TestKind{}),
			loadContent:     okLoader,
		},
		{
			Name:    "All three kinds run together",
			wantErr: false,
			Ctx: strategy.TestContext{
				Target: server.URL,
				Args:   []string{"pre", "resp", "struct"},
			},
			expectedResults: 3,
			antiBotFlag:     false,
			getTest: byKind(map[string]Tests.TestKind{
				"pre":    Tests.PreResponse,
				"resp":   Tests.Response,
				"struct": Tests.Structure,
			}),
			loadContent:   okLoader,
			wantLoadCalls: 1,
		},
		{
			// The regression this split exists to prevent: a blocked main request used to
			// cancel the whole scan. Only the Response test may be lost, and the failure
			// itself is still reported.
			Name:    "Blocked request only skips the response phase",
			wantErr: false,
			Ctx: strategy.TestContext{
				Target: server.URL,
				Args:   []string{"pre", "resp", "struct"},
			},
			expectedResults: 3,
			antiBotFlag:     false,
			getTest: byKind(map[string]Tests.TestKind{
				"pre":    Tests.PreResponse,
				"resp":   Tests.Response,
				"struct": Tests.Structure,
			}),
			loadContent:   blockedLoader,
			wantLoadCalls: 1,
		},
		{
			Name:    "No response test means no request is issued",
			wantErr: false,
			Ctx: strategy.TestContext{
				Target: server.URL,
				Args:   []string{"pre", "struct"},
			},
			expectedResults: 2,
			antiBotFlag:     false,
			getTest: byKind(map[string]Tests.TestKind{
				"pre":    Tests.PreResponse,
				"struct": Tests.Structure,
			}),
			loadContent:   okLoader,
			wantLoadCalls: 0,
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

			var loadCalls int32
			headerStrategy := InitializeHeaderStrategy(
				func(target string, useAntiBotDetection bool) (*http.Response, *strategy.RequestInfo) {
					atomic.AddInt32(&loadCalls, 1)
					return val.loadContent(target, useAntiBotDetection)
				}, val.getTest,
				func(target string, params []string) *string {
					return &target
				},
				func(target string) *url.URL {
					return &url.URL{Scheme: "https", Host: target}
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
			if got := atomic.LoadInt32(&loadCalls); got != val.wantLoadCalls {
				t.Errorf("Expected %d content load(s), but got %d", val.wantLoadCalls, got)
			}
		})
	}
}
