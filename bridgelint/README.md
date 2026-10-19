# bridgelint

`bridgelint` checks [mautrix bridgev2](https://pkg.go.dev/maunium.net/go/mautrix/bridgev2) bridges for
error-reporting and reliability mistakes that tend to repeat across bridges: Matrix handlers that return
bare errors, login errors that turn into a 500, bridge states with raw error text or the wrong user action,
background loops that fail silently, and a few general Go reliability problems.

It's type-aware: functions are classified by the bridgev2 interface their receiver implements
(`NetworkAPI`, `LoginProcess*`, `NetworkConnector`), not by name.

## Usage

```sh
go install github.com/beeper/pre-commit-go/bridgelint@latest
bridgelint ./...            # errors and warnings; exits 1 if there are errors
bridgelint -verbose ./...   # also show info-level findings
bridgelint -fix ./...       # apply the autofixes for the findings shown
bridgelint -rules           # list rules
```

As a pre-commit hook:

```yaml
- repo: https://github.com/beeper/pre-commit-go
  rev: <version>
  hooks:
    - id: bridgelint
      # args: [-baseline=bridgelint.baseline.json]
```

The hook runs on the whole module (`./...`) whenever a Go file changes, because the rules need type
information from every package.

### Severity

- `error` findings fail the run.
- `warning` findings are reported but don't fail it.
- `info` findings only show with `-verbose`.

Severities can be changed per rule in the config, so a new rule can start as a warning while a bridge
burns down existing hits.

### Baselines

To adopt bridgelint on a bridge with existing findings:

```sh
bridgelint -baseline=bridgelint.baseline.json -write-baseline ./...
bridgelint -baseline=bridgelint.baseline.json ./...   # only reports findings not in the baseline
```

Findings are matched by rule, file and a hash of the normalised source line, so they survive unrelated
edits that move lines around.

### Suppressing a finding

Put a comment on the line, or the line above:

```go
//bridgelint:ignore BS002 removed-from-team is deliberately left on the RELOGIN default
```

A reason is required. An ignore without rule IDs or without a reason is reported as `BL000`.

Functions that map errors to message statuses or `RespError`s can be marked so their results count as
handled:

```go
//bridgelint:status-mapper
func wrapSendError(err error) error { ... }
```

### Configuration

`bridgelint` reads the nearest `.bridgelint.yaml` above each package (stopping at `go.mod`), or the file
given with `-config`. Everything is optional:

```yaml
error_prefix: slack                      # BS004: codes must look like slack-<reason>
code_format_allowlist: ["slack-%s"]      # BS004: fmt.Sprintf formats known to be bounded
status_mappers: [wrapSendError]          # MSS001: functions whose result is a proper status
login_mappers: [wrapLoginError]          # LP001: functions whose result is a proper RespError
classifiers: [slackAPIErrorCode]         # MSS006: typed error-code accessors
network_packages:                        # which imports count as network libraries (see below)
  - github.com/slack-go/slack
  - go.mau.fi/mautrix-slack/pkg/...
disconnect_events:                       # BS009: event types that signal a dropped connection
  github.com/slack-go/slack: ["*DisconnectedEvent", "*FatalConnectionErrorEvent"]
helper_depth: 3                          # how far errors are followed through same-package helpers
disable: [GR009]
severity:
  GR012: info
```

By default, errors returned from any non-stdlib import (plus `net/http`) count as raw network errors,
except mautrix itself, zerolog, and packages that look like a database or ID layer (`*db`, `database`,
`store`, `*id`, `*ids`). Set `network_packages` to be explicit.

## Rules

### Message statuses (MSS)

Matrix handlers are the `HandleMatrix*`/`PreHandleMatrix*` methods of a `NetworkAPI` implementation.
Their errors become message statuses, and a bare error becomes `FAIL_RETRIABLE` with no message.

| Rule | Severity | Flags |
|---|---|---|
| MSS001 | error | A handler returns `errors.New`/`fmt.Errorf` or a raw library error, directly or through a same-package helper. |
| MSS002 | error | A permanent rejection stays retriable: `ErrorReason` `Unsupported`/`NoPermission`/`TooOld` without `WithStatus(event.MessageStatusFail)`, or a message that reads as permanent ("not supported", "too large", "not allowed"…). Use a `bridgev2.Err*` sentinel where one fits. |
| MSS003 | warning | Raw error text shown to users: `WithErrorAsMessage()` on a library error or on `fmt.Errorf` that formats another error or status code, or `WithMessage(err.Error())`. |
| MSS004 | warning | `WithIsCertain(true)` on a timeout. |
| MSS005 | info | A status with a message and certainty but no `ErrorReason`. |
| MSS006 | warning | The package has a typed error classifier (a `func(error) string/int` that calls `errors.As`) but a handler returns library errors without using it. |

### Bridge states (BS)

| Rule | Severity | Flags |
|---|---|---|
| BS001 | info | An explicit `UserActionRelogin` on `BAD_CREDENTIALS`; bridgev2 already defaults to it. |
| BS002 | error | A restriction, ban, checkpoint or consent code that isn't `BAD_CREDENTIALS` + `OPEN_NATIVE`, or `UserActionRestart` with `BAD_CREDENTIALS`. Autofix sets `OPEN_NATIVE`. |
| BS003 | error | `Message` built from `err.Error()` or `fmt.Sprintf(..., err)`. Warning when the code has a `BridgeStateHumanErrors` entry, since the text is then silently discarded. |
| BS004 | error | An error state with no `Error` code, a code that doesn't match `<error_prefix>-<reason>`, or a code built with `fmt.Sprintf`. |
| BS005 | warning | A code with no `Message` and no `BridgeStateHumanErrors` entry anywhere in the linted packages. |
| BS006 | warning | `UNKNOWN_ERROR` for a raw network error in a function that never checks for rate limits, timeouts or status codes. |
| BS007 | error | In `Connect` or a goroutine, `TRANSIENT_DISCONNECT` followed by `return`/`break` with nothing scheduling a reconnect. |
| BS008 | error | In a long-running goroutine loop (or an `On*Error`/`Handle*Error` callback), a network error that is only logged, where nothing in that goroutine sends a bridge state. |
| BS009 | warning | An event-handler type switch for a configured library with no case for its disconnect events. |
| BS010 | warning | `TRANSIENT_DISCONNECT` under a 401/403/auth check. |
| BS011 | warning | `BAD_CREDENTIALS` for every connect error: in a `default`/`else` branch, or directly under `if err != nil` after a `Connect` call. |

`UNKNOWN_ERROR` followed by `return` isn't flagged by BS007: bridgev2 reconnects automatically on
`UNKNOWN_ERROR`.

### Login and provisioning (LP)

Login methods are the methods of `LoginProcess*` implementations plus `NetworkConnector.CreateLogin`.
Provisioning methods are `ResolveIdentifier`, `CreateGroup`, `CreateChatWithGhost`, `SearchUsers` and
`GetContactList`. A plain error from these becomes a bare 500 `M_UNKNOWN`.

| Rule | Severity | Flags |
|---|---|---|
| LP001 | error | A login or provisioning method returns a plain or raw error instead of a `bridgev2.RespError`. |
| LP002 | error | A rate-limit `RespError` (`M_LIMIT_EXCEEDED`, or "rate limit"/"too many requests"/"flood"/"slow down") whose status isn't 429. Autofix sets 429. |
| LP003 | warning | A temporary or upstream failure returned as 4xx. |
| LP004 | warning | A `RespError` status copied from a network error code (`StatusCode: te.Code`). |
| LP005 | warning | A `RespError` literal without `StatusCode`, which is sent as 500. |
| LP006 | error | A provisioning method logs an error and carries on, so the caller is told it succeeded. |
| LP007 | info | A `RespError` literal for a standard Matrix code; use `mautrix.MLimitExceeded.WithMessage(...)` and friends so the status can't drift from the code. Autofix rewrites it. |
| LP008 | info | A login method re-checks a submitted field against the same regex as the field's `Pattern`. |

### Error plumbing (EP)

| Rule | Severity | Flags |
|---|---|---|
| EP001 | error | Errors matched by string: `err.Error() == "..."`, `switch err.Error()`, `strings.Contains(err.Error(), ...)`. |
| EP002 | warning | In library packages (ones that don't import bridgev2), an HTTP status formatted into a plain error, so callers can't tell 429 from 403 from 5xx. |
| EP003 | info | `errors.Join` returned from a Matrix handler or used as a user-facing message. |

### General reliability (GR)

| Rule | Severity | Flags |
|---|---|---|
| GR001 | warning | An `*http.Response` whose body is never closed and isn't passed on. |
| GR002 | warning | `http.Get`/`Post`/`Head`, `http.NewRequest` without a context, `http.DefaultClient`, or `http.Client{}` without `Timeout`. |
| GR003 | warning | A request built once with a body and re-sent with `Do` inside a loop; the body is empty on retries. |
| GR004 | error | `os.Exit`, `log.Fatal*`/`Panic*`, zerolog `Fatal()`/`Panic()` or `panic` outside `main`, `init` and `Must*` functions. |
| GR007 | warning | A blocking channel send in a Matrix handler (no `select` with `default` or `ctx.Done()`). |
| GR008 | warning | A cursor/seq/checkpoint field assigned after a loop that calls `QueueRemoteEvent`, before the events are handled. |
| GR009 | warning | A package-level map, slice, struct or pointer written at runtime in a bridge package, shared by every login. |
| GR011 | warning | `GetCapabilities` changes `RoomFeatures` fields but never the `ID`, so clients cache the wrong features. |
| GR012 | warning | A map field that's only ever inserted into. |
| GR013 | warning | `LogoutRemote` that never disconnects or stops the client. |

### Not implemented yet

- MSS004's second half: missing certainty on failures returned before the network call.
- Retry counters that never reset (GR005), unchecked indexing of protocol data (GR006; `nilaway` covers
  part of it) and unlocked metadata maps (GR010; run tests with `-race`).
- A golangci-lint plugin. The analyzers in `rules` are plain `go/analysis` analyzers, so wiring one up
  is mostly boilerplate.

## Development

```sh
go test ./bridgelint/...
```

Tests use `analysistest` against small stub copies of the bridgev2 API under `rules/testdata/src`.
Each rule has positive cases (`// want`) next to the house pattern that should pass.
