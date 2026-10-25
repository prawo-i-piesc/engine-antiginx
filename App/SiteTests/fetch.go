package SiteTests

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

// FetchedPage is one response with its body already read and its connection closed, so a
// test never has to manage a response body itself.
type FetchedPage struct {
	Status int         // HTTP status code
	Header http.Header // Response headers
	Body   []byte      // At most the requested number of body bytes
}

// BaseURL is the scheme and host of a target, the origin that tests probing fixed paths
// such as /robots.txt append their path to.
func BaseURL(target *url.URL) string {
	return target.Scheme + "://" + target.Host
}

// Fetch requests a URL with GET and reads at most maxBytes of its body. See FetchRequest for
// what is returned on failure.
func Fetch(client *http.Client, target string, maxBytes int64) (FetchedPage, error) {
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return FetchedPage{}, err
	}
	return FetchRequest(client, request, maxBytes)
}

// FetchRequest sends a prepared request and reads at most maxBytes of the body, whatever the
// status. When the request itself fails the page is empty; when only reading the body fails
// the page still carries the status and headers alongside the error.
func FetchRequest(client *http.Client, request *http.Request, maxBytes int64) (FetchedPage, error) {
	response, err := client.Do(request)
	if err != nil {
		return FetchedPage{}, err
	}
	defer func() {
		if cerr := response.Body.Close(); cerr != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", cerr.Error())
		}
	}()

	page := FetchedPage{Status: response.StatusCode, Header: response.Header}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes))
	if err != nil {
		return page, err
	}
	page.Body = body
	return page, nil
}

// ProbeAll runs probe for every item, at most concurrency at a time, and returns the results
// probe reported as found, in the order of the items, so a report does not depend on which
// request happened to finish first.
func ProbeAll[T, R any](items []T, concurrency int, probe func(T) (R, bool)) []R {
	results := make([]R, len(items))
	found := make([]bool, len(items))

	var group sync.WaitGroup
	slots := make(chan struct{}, max(concurrency, 1))
	for index, item := range items {
		group.Add(1)
		slots <- struct{}{}
		go func(index int, item T) {
			defer group.Done()
			defer func() { <-slots }()
			results[index], found[index] = probe(item)
		}(index, item)
	}
	group.Wait()

	kept := make([]R, 0, len(items))
	for index, result := range results {
		if found[index] {
			kept = append(kept, result)
		}
	}
	return kept
}
