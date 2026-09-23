# Helpers: target URLs, parameters, and utilities

`App/Helpers` contains small utilities used by the parser and scan strategies, plus a file-reading adapter. Its Go package name is `helpers`.

## Target URLs

`InitializeTargetFormatter()` returns a stateless `*TargetFormatter`. `Format(target, params) *string` prefixes `http://` if the test IDs include exactly `https` or `hsts`; otherwise it prefixes `https://`. Pass a hostname without a scheme. A target starting with the literal lowercase prefix `http` triggers a panic with `Errors.Error` code `100` (including unusual strings that merely start with `http`); this is not full hostname validation. `CanonicalURL(target) *url.URL` always parses `https://` plus the target, regardless of the test IDs, and panics with code `101` if parsing fails. The canonical URL is used for PreResponse and Structure tests; the formatted URL is used for Response tests so the `https`/`hsts` checks can observe HTTP behavior.

```go
formatter := helpers.InitializeTargetFormatter()
responseURL := formatter.Format("example.com", []string{"https"}) // http://example.com
canonicalURL := formatter.CanonicalURL("example.com")          // https://example.com
```

## JSON input validation

`DeserializeTests(bytes)` decodes JSON into `types.TestJson`, returning `(nil, *Errors.Error)` with code `100` on a decoding failure. `CheckParameters(givenParams)` validates parameter names against `config.Params`, argument counts and permitted values, and repeated parameters or arguments. It mutates the input: nil `Arguments` becomes an empty slice, and an optional parameter with no arguments gets its `DefaultVal` appended. Argument whitelist and duplicate checks run only when `token.Arguments` is nonempty.

| `Errors.Error` code | `CheckParameters` condition |
|---|---|
| `101` | Nil entry in the parameter list. |
| `102` | Parameter name not in `config.Params`. |
| `103` | Repeated parameter name. |
| `104` | Missing required argument. |
| `105` | More than one argument when `ArgCount == 1`. |
| `106` | Argument outside the parameter's allowed values. |
| `107` | Repeated argument. |

## Other APIs

| API | Behavior |
|---|---|
| `MinInt(a, b)` | Returns the smaller `int`. |
| `ContainsAnySubstring(s, subs)` | Case-insensitive search for any substring; an empty substring matches. |
| `RemoveDuplicates(slice)` | Removes duplicate strings, preserving first-occurrence order; returns `nil` for empty input. |
| `StringInSlice(slice, item)` | Case-sensitive, exact membership check. |
| `AnyStringInSlice(slice, items)` | Checks whether any item in `items` occurs in `slice`. |
| `FileReader.ReadFileW(filename)` | Interface for reading file bytes. |
| `CreateFileReader()` / `OSFileReader.ReadFileW` | Adapter around `os.ReadFile`, returning its bytes and error. |
