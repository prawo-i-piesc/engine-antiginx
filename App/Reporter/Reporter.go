package Reporter

type Reporter interface {
	StartListening() <-chan int
}
