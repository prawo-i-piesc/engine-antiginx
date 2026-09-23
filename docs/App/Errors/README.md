# Errors: structured application errors

`App/Errors` defines `Error`, a structured error with a code, source, and retry hint. The package itself neither panics nor recovers: callers may return `*Errors.Error` as an ordinary Go `error` or panic with an `Errors.Error` value. Recovery is handled elsewhere, for example in `GlobalHandler`.

## Fields and formatting

| `Error` field | Type / JSON key | Meaning |
|---|---|---|
| `Code` | `int` / `Code` | Code assigned at the error site. |
| `Message` | `string` / `Message` | Description of the problem. |
| `Source` | `string` / `Source` | Component reporting the error. |
| `IsRetryable` | `bool` / `IsRetryable` | Hint that retrying may help; this type does not retry anything. |

`(*Error).Error() string` uses this format:

```text
[<Source>] Error <Code>: <Message> (Retryable: true|false)
```

For example, `Error{Code: 101, Message: "Network timeout occurred", Source: "HTTP", IsRetryable: true}` formats as `[HTTP] Error 101: Network timeout occurred (Retryable: true)`. Because the method has a pointer receiver, `*Errors.Error` implements Go's `error` interface; `Errors.Error` does not. Do not call the method on a nil pointer.

Codes are neither an enum nor validated ranges. Code `100`, for instance, is used in both target formatting and JSON deserialization; the global panic handler uses `999` for unexpected panics. Do not infer the error's source from its code alone: inspect `Source` and `Message` too.
