// Package Reporter provides result consumers.
package Reporter

// Reporter consumes results and signals completion.
type Reporter interface {
// StartListening returns a channel carrying the failure count.
	StartListening() <-chan int
}
