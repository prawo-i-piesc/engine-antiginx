package CacheControlTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"io"
	"net/http"
	"strings"
	"testing"
)

func run(headers map[string]string, cookie string, body string) SiteTests.TestResult {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	if cookie != "" {
		h.Add("Set-Cookie", cookie+"=abc; Path=/")
	}
	resp := &http.Response{Header: h, Body: io.NopCloser(strings.NewReader(body))}
	return New().RunTest(SiteTests.ResponseTestParams{Response: resp, Body: []byte(body)})
}

func TestCacheControl(t *testing.T) {
	login := `<form><input type="password" name="p"></form>`
	cases := []struct {
		name    string
		headers map[string]string
		cookie  string
		body    string
		want    SiteTests.ThreatLevel
	}{
		{"public session", map[string]string{"Cache-Control": "public, max-age=600"}, "PHPSESSID", "", SiteTests.High},
		{"s-maxage password", map[string]string{"Cache-Control": "s-maxage=60"}, "", login, SiteTests.High},
		{"max-age only", map[string]string{"Cache-Control": "max-age=3600"}, "sessionid", "", SiteTests.Medium},
		{"pragma only", map[string]string{"Pragma": "no-cache"}, "", login, SiteTests.Medium},
		{"no-store", map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache"}, "sid", login, SiteTests.None},
		{"private max-age", map[string]string{"Cache-Control": "private, max-age=60"}, "sid", "", SiteTests.None},
		{"not sensitive", map[string]string{"Cache-Control": "public, max-age=600"}, "theme", "<p>hi</p>", SiteTests.None},
		{"no headers", nil, "sid", "", SiteTests.Low},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := run(c.headers, c.cookie, c.body).ThreatLevel; got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
