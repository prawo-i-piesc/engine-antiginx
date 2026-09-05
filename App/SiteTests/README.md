# SiteTests

Every security test the engine runs, plus the framework they plug into. "Site tests" to
distinguish them from Go unit tests — these examine a target website, not this codebase.

Two Go files sit in this directory and neither is a test: `Types.go` is the framework —
the types every test reports through — and `helpers.go` is the shared toolbox. Everything
else is a test, in its own directory, in its own package.

## Directory layout

```
SiteTests/
├── Types.go                    the framework
├── helpers.go                  reusable functions for tests
├── README.md                   this file
├── HSTSTest/
│   ├── README.md               what the test is for
│   ├── core.go                 the test itself
│   ├── config.go               what tunes it
│   └── data.go                 what it knows
└── PhishingURLTest/
    ├── README.md
    ├── core.go
    ├── config.go
    ├── data.go
    └── modules/                stages, for a test that has several
        ├── domainimpersonation.go
        └── urlparameters.go
```

The split is by **rate of change**, not by size. A test's logic is rewritten rarely, its
thresholds are adjusted occasionally, and its datasets — the brands it knows, the paths it
considers dangerous, the headers it recognises — change constantly, because the things
being detected change. Keeping the three apart means the frequent edit is a small edit to
an obvious file, made without reading the algorithm around it.

| File | Holds | Rule |
|---|---|---|
| `README.md` | What the test is for, why its findings matter, the threat scale it reports, what it returns | The documentation lives here, not in godoc. Code comments are kept to one line. |
| `core.go` | `New()`, the orchestration, the assembled verdict | The only file you must read to know what a test does |
| `config.go` | Identity constants, thresholds, confidence levels, timeouts | Numbers only — nothing that decides |
| `data.go` | Reference datasets | Data only — nothing that decides |
| `modules/` | Stage implementations, as a package of its own | Only for a test with several stages |

**`modules/` owns no data.** `core.go` injects the datasets from `data.go` and the limits
from `config.go`, so the dependency runs one way (`core → modules`) and a stage can be
exercised on its own. Go would reject the reverse as an import cycle.

**`modules/` is by convention private to its test.** Go cannot enforce that for a directory
named `modules` — renaming it to `internal` would make the compiler enforce it, at the cost
of an extra directory level.

## Shared helpers

`helpers.go` holds what more than one test needs, so a second test never re-solves a
problem the first one already solved. A function earns a place here when it is used by at
least two tests, or when it is general enough that the next test would otherwise write its
own — the point is to stop five slightly different header parsers from existing.

| Function | Does |
|---|---|
| `NormalizeHeaderValue(value)` | Trims and lowercases a header value for comparison |
| `SplitHeaderList(header, sep)` | Splits a header, trimming parts and dropping empties |
| `ParseDirectives(header)` | Parses a `;`-separated directive header into name → values. First occurrence of a repeat wins, as browsers resolve it |
| `DirectiveValue(header, name)` | One directive's values, and whether it was present — a directive with no values is not an absent one |
| `ContainsAnyFold(haystack, needles)` | Whether any needle appears, ignoring case |
| `FindAllFold(haystack, needles)` | Which needles appear, ignoring case, in the order given |
| `ContainsStandaloneToken(haystack, token)` | Whether a token appears delimited by non-alphanumerics, so `google` does not match inside `googleapis` |
| `UniqueStrings(values)` | Deduplicates, preserving first-seen order |
| `HighestThreatLevel(levels...)` | The most severe level given |
| `EscalateThreatLevel(level)` | Raises a level by one, capped at `Critical` — how a test says several findings together mean more than the worst alone |
| `FormatDuration(seconds)` | Renders seconds as the largest whole unit that fits |

Two things deliberately stay out. `CookieSecurityTest` keeps its own duration formatter
because its wording differs (`1 year(s) 30 day(s)` against `1 year`), and unifying them
would change what reports say. Anything that encodes one test's judgement — its thresholds,
its datasets — belongs in that test's `config.go` or `data.go`, never here.

## Uniform names

Every test package declares the same symbols. This is what lets the registry, and any
future automation that discovers tests by scanning this directory, work without knowing
which test it is looking at.

| Symbol | In | Is |
|---|---|---|
| `New()` | `core.go` | The constructor, returning one of the three test types |
| `TestId` | `config.go` | The `--tests` identifier |
| `TestName` | `config.go` | The display name carried in every result |
| `TestDescription` | `config.go` | One line, shown in help |
| `TestCategory` | `config.go` | `Headers`, `Encryption`, `App-Configuration`, `Phishing`, `Bot-Protection` |

## Execution phases

A test declares what it needs, and that decides when the scheduler runs it. You never
select a phase — it follows from the test.

| Kind | Needs | Behaviour |
|---|---|---|
| `PreResponseTest` | The target URL only | Runs immediately, in parallel with the page fetch. Still reports when the target is unreachable or blocked. |
| `ResponseTest` | The fetched page | The only phase skipped when the main request fails |
| `StructureTest` | The target's configuration | Opens its own connections — TLS handshake, sitemap fetch |

The split is why a blocked target still produces a report: only the Response tests are
skipped, and the report names them.

## Threat levels

| | Level | Means |
|---|---|---|
| 0 | `None` | No issue found; the configuration meets what is expected |
| 1 | `Info` | Worth knowing, no security impact |
| 2 | `Low` | Minor issue, low exploitability |
| 3 | `Medium` | Needs attention |
| 4 | `High` | Serious, with real impact |
| 5 | `Critical` | Severe, remediate immediately |

Levels serialise to their names in JSON, not to numbers.

## What a test returns

```go
type TestResult struct {
    Name        string      // the test's display name
    Certainty   int         // 0-100, confidence in this finding
    ThreatLevel ThreatLevel // the classification above
    Metadata    any         // test-specific detail; each test's README documents its shape
    Description string      // the finding, in the operator's terms
}
```

`Certainty` is about confidence in the finding, not about severity. A deterministic check
reports 100 whatever it found; a heuristic reports lower, and a test whose sources were
unreachable reports lower still.

## Adding a test

1. Create `SiteTests/<Name>Test/`.
2. Write `README.md`, `core.go`, `config.go` and — if it has data — `data.go`.
3. Register the package's `New()` in [`App/Registry`](../Registry).
4. Add the identifier to the `--tests` whitelist in [`App/parser/config`](../parser/config).
5. Add the test to the table in [`docs/QuickStart/CLI.md`](../../docs/QuickStart/CLI.md) and
   to the nav in [`mkdocs.yml`](../../mkdocs.yml) — the docs build runs with `strict: true`
   and fails on a page that is not in the nav.
