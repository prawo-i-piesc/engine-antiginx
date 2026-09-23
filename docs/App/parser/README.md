# Parameter parser

`App/parser` routes the command in `userParameters[1]` (normally `os.Args[1]`) to a `Parser` and its matching `execution.Formatter`. Use `CreateResolver().Resolve(args)` to get both, then call `Parse(args)` to obtain `[]*types.CommandParameter` (`Name` and `Arguments`). The resolver panics with `Errors.Error` code 100 for fewer than two tokens or 101 for an unknown command. Supported commands are exactly `test`, `json`, `rawjson` and `help`; the map is initialized with parser and formatter instances. `test`, `json` and `rawjson` use the normal formatter, while `help` uses the help formatter.

## Input modes

| Command | Parser | Input and behavior |
|---|---|---|
| `test` | `CreateCommandParser()` | Reads tokens from index 2 using `config.Params`; requires at least three tokens. Parameters and their values are returned in input order. The parser itself does not inspect token 1 (the resolver selects the mode). |
| `json` | `CreateJsonParser(fileReader)` | Reads the filename at index 2 via the injected `helpers.FileReader`, deserializes `types.TestJson` (`Target` and nonempty `Parameters`), validates the file's `Parameters` via `helpers.CheckParameters`, and prepends a `--target` parameter containing `Target`. Requires at least three tokens. |
| `rawjson` | `CreateRawJsonParser(io.Reader)` | Reads all bytes from the injected reader (stdin in the default resolver), deserializes the same shape, requires a nonempty target and nonempty parameters, prepends `--target`, then validates the **whole** resulting list with `helpers.CheckParameters`. It does not inspect the argument slice. |
| `help` | `CreateHelpParser()` | For each token from index 2, requires a name present in `config.Params` and returns it with nil arguments. With no such tokens, returns an empty slice; unknown names panic with code 100. |

Example file/stdin document:

```json
{
  "Target": "example.com",
  "Parameters": [
    {"Name": "--tests", "Arguments": ["https", "hsts"]}
  ]
}
```

## `test` parameters and validation

`config.Params` is the static configuration (exported as a mutable map). An empty `Arguments` whitelist accepts any value; `ArgRequired` marks parameters intended to have at least one argument (subject to the trailing-parameter edge case below); `ArgCount: 1` is single-valued, `-1` is multi-valued, and `0` is a flag. The parser recognizes these active names:

| Name | Values |
|---|---|
| `--target`, `--taskId` | One required, unrestricted value each. |
| `--tests` | One or more required values from `https`, `hsts`, `serv-h-a`, `csp`, `cookie-sec`, `js-obf`, `xframe`, `permissions-policy`, `x-content-type-options`, `referrer-policy`, `ssl-cert`, `cross-origin-x`, `sitemap`, `phishing-url`, `bot-protection`, `dns-reputation`, `favicon-origin`. |
| `--userAgent` | Optional value when the flag is present; omitting the value uses `Scanner/1.0`. |
| `--antiBotDetection`, `--all` | Flags with zero arguments. |

The parser consumes the arguments of a required parameter until it sees another recognized parameter. It rejects an invalid whitelisted value (304), an unexpected token (304), duplicate values within a required parameter's argument list (305), and excess values for a single-value parameter (306). Missing arguments when a required parameter is followed by another parameter or is last trigger 303. An optional parameter takes its next token as its value if that token is not a recognized parameter; zero-argument flags reject such a token with 306. There is no general check for repeated parameter **names**, no automatic insertion of missing required parameter names, and the parser does not require the second token to literally be `test` when called directly. The trailing required-parameter path does not explicitly reject an empty argument list; do not treat parsing alone as complete plan validation.

Errors from parsers are surfaced as panics with `Errors.Error` (or the error returned by deserialization/validation). The JSON file parser uses codes 100 for missing filename position, 101 for missing target/parameters, 102 for empty filename, 103 for read failure and 104 for empty file; deserialization and `helpers.CheckParameters` may supply their own codes. Raw JSON uses 100 for reader failure and 101 for missing target/parameters; help uses 100 for an unknown parameter. See [Runner](../Runner/README.md) for execution after formatting.
