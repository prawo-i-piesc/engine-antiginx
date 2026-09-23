# Runner

`App/Runner` coordinates an already constructed `execution.Plan` with a `Reporter.Resolver`. It does **not** parse CLI arguments or fetch the target directly; parsing happens before orchestration, fetching belongs to the plan's strategies, and reporter selection belongs to the resolver.

## API

`CreateJobRunner() *jobRunner` creates a stateless runner. Call `Orchestrate(execPlan *execution.Plan, repResolver Reporter.Resolver)` with a populated plan and a resolver (for example `Reporter.NewResolver()`). The plan supplies `Target`, `TaskId`, `Contexts`, `AntiBotFlag`, `IsHelp` and an ordered slice of `Strategies`.

`Orchestrate` reads the plan, then:

1. Unless `IsHelp` is true, rejects an empty strategy list or empty contexts with `Errors.Error` code 100 (panic). It does not check for a nil plan or resolver.
2. Creates a buffered `chan strategy.ResultWrapper` (capacity 100) and a `sync.WaitGroup`.
3. Calls `repResolver.Resolve(channel, TaskId, Target, 5, 2, Strategies)` and starts the selected reporter with `StartListening()`.
4. Iterates over strategies in order, calling `Execute(Contexts[strategy.GetName()], channel, &wg, AntiBotFlag)`. Each strategy controls whether work is asynchronous; the runner itself does not launch a goroutine per strategy. Missing context keys yield the map's zero value.
5. Waits for strategy work to finish, closes the result channel, then waits for the reporter's completion value. If the reported failure count is positive, prints `Engine failed to send N requests` to **stdout**.

The reporter must consume results while strategies produce them, return a channel that eventually yields one integer, and allow completion after the result channel closes. Strategies must register any asynchronous work with the supplied wait group and stop sending before it is closed. Otherwise `Orchestrate` can block or a late send can panic. It does not return the failure count or an error; errors in called components may panic. The reporter selection rules and backend retry behavior are described in [Reporter](../Reporter/README.md).

`mocktypes.go` contains simple exported test doubles used by the runner tests; they are not the production reporting path.
