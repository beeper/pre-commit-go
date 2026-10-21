# bridgelint

`bridgelint` checks [mautrix bridgev2](https://pkg.go.dev/maunium.net/go/mautrix/bridgev2) bridges for
error-reporting and reliability mistakes that tend to repeat across bridges: Matrix handlers that return
bare errors, login errors that turn into a 500, bridge states with raw error text or the wrong user action,
background loops that fail silently, and a few general Go reliability problems.

It's type-aware: functions are classified by the bridgev2 interface their receiver implements
(`NetworkAPI`, `LoginProcess*`, `NetworkConnector`), not by name.

It's a best-practices linter, so it prefers missing a problem to flagging correct code. Rules only fire
on patterns that are wrong wherever they appear; heuristics that need knowledge of the protocol or the
author's intent aren't included. If a rule needs suppression comments to be usable on a bridge, fix the
rule.

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

`bridgelint` runs itself as a `go vet` tool (`go vet -vettool=bridgelint -json`), so each package is
analysed in its own process, in dependency order, with what's learned about its functions passed to
importers through the build cache. Packages that haven't changed aren't analysed again.

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

This should be rare. Put a comment on the line, or the line above:

```go
//bridgelint:ignore BS002 removed-from-team is deliberately left on the RELOGIN default
```

A reason is required. An ignore without rule IDs or without a reason is reported as `BL000`.

Rules marked "name heuristic" in the tables below have no type information to work from: a cursor field
or a stopping method is only recognisable by its name. They're warnings for that reason, and shouldn't
be promoted to errors. Every other rule matches on types, and no rule matches on source text.

Errors are followed through same-package helpers, so a mapper that returns `WrapErrorInStatus(...)` or a
`RespError` is recognised automatically. Mappers that sometimes return the error unchanged can be listed
in `status_mappers`/`login_mappers` in the config. A function with a deferred closure that maps its named
error result (`if err != nil { err = wrap(err) }`) is treated as mapped.

### Configuration

`bridgelint` reads the nearest `.bridgelint.yaml` above each package (stopping at `go.mod`), or the file
given with `-config`. Everything is optional:

```yaml
error_prefix: slack                      # BS004: codes must look like slack-<reason>
code_format_allowlist: ["slack-%s"]      # BS004: fmt.Sprintf formats known to be bounded
status_mappers: [wrapSendError]          # MSS001: functions whose result is a proper status
login_mappers: [wrapLoginError]          # LP001: functions whose result is a proper RespError
classifiers: [slackAPIErrorCode]         # MSS006: typed error-code accessors
auth_errors: [slack.ErrInvalidAuth]      # BS010, BS011: the library's rejected-session sentinels
network_packages:                        # packages whose functions all count as reaching the network (see below)
  - github.com/slack-go/slack
  - go.mau.fi/mautrix-slack/pkg/...
disconnect_events:                       # BS009: event types that signal a dropped connection
  github.com/slack-go/slack: ["*DisconnectedEvent", "*FatalConnectionErrorEvent"]
helper_depth: 3                          # how far errors are followed through same-package helpers
disable: [GR009]
severity:
  GR012: info
```

An error counts as a raw network error when it comes from a function that can reach the network.
bridgelint follows calls from source through every package the bridge depends on, except the standard
library, bridgev2 and `go.mau.fi/util`, down to these standard library calls:

- an HTTP round trip: `Do`/`RoundTrip` taking a `*Request` on any client (net/http or a fork like fhttp,
  whose transports send from goroutines), and `http.Get` and friends;
- a dial in `net` or `crypto/tls`;
- a read or write on a `net` or `crypto/tls` connection.

Calls through interfaces declared outside the standard library are resolved against the implementations
visible from the calling package, so a library's transport interface resolves once the bridge imports
the implementation. Goroutines count when the function waits on a channel they send to. Function
literals count when they're called or passed to a call, not when they're stored.

Libraries that keep a persistent connection usually write to it in ways that can't be followed without
tracking values: through a `bufio.Writer` around the connection (websocket libraries), a chain of func
values (MTProto), or an interface whose implementation the library can't see. So a function also counts
when it takes a `context.Context`, belongs to a network library or the module being linted, and makes
one of these calls: a context-taking call through a func value or through an interface with no visible
implementation, or a read or write on a `bufio.Reader`/`Writer` kept in a struct field. A network
library is a package that has functions reaching the network, or imports one. A context-taking helper
that doesn't do any of this (an audio converter, a database layer) never counts.

Functions in the module that return bridgev2 statuses themselves, like message converters, are followed
instead, so the statuses they return count as mapped. Package-level error values count as network errors
when their package is a network library. Set `network_packages` to make every function in a package
count as reaching the network.

Plain `errors.New`/`fmt.Errorf` errors that don't wrap a network error are treated as internal
invariants (bad portal IDs, impossible states) and aren't reported, except when `CreateLogin` returns
one to reject a flow ID (LP001). Error rules don't match on error message text.

Returns inside a function literal aren't followed, so a handler that does its work in a closure
(`return c.withLock(func() error { ... })`) isn't checked.

Rules that depend on newer bridgev2 behaviour check the module's `maunium.net/go/mautrix` version (from
`go list -m`) and stay quiet when the pinned version doesn't have it.

## Rules

### Message statuses (MSS)

Matrix handlers are the `HandleMatrix*`/`PreHandleMatrix*` methods of a `NetworkAPI` implementation.
Their errors become message statuses, and a bare error becomes `FAIL_RETRIABLE` with no message.

| Rule | Severity | Flags |
|---|---|---|
| MSS001 | error | A handler returns a network error unmapped: as is, or wrapped in `fmt.Errorf`, directly or through a same-package helper. |
| MSS002 | error | A permanent rejection stays retriable: `ErrorReason` `Unsupported`/`NoPermission`/`TooOld` without `WithStatus(event.MessageStatusFail)`. |
| MSS003 | warning | Raw error text shown to users: `WithErrorAsMessage()` on a library error or on `fmt.Errorf` that formats another error or status code, or `WithMessage(err.Error())`. |
| MSS004 | warning | `WithIsCertain(true)` on a timeout: `context.DeadlineExceeded`, `os.ErrDeadlineExceeded` or `net.Error.Timeout()`. A library's own timeout error isn't recognised. |
| MSS005 | info | A `MessageStatus` literal with a message and certainty but no `ErrorReason` (`WrapErrorInStatus` already defaults it to `GenericError`). |
| MSS006 | warning | The package has a typed error classifier (a `func(error) string/int` named like `*Code`/`*Kind`/`*Status` that calls `errors.As`, or one listed in `classifiers`) but a handler returns network errors without using it. Name heuristic. |

### Bridge states (BS)

| Rule | Severity | Flags |
|---|---|---|
| BS001 | info | An explicit `UserActionRelogin` on `BAD_CREDENTIALS`, when the pinned mautrix already defaults to it (after v0.32.0). |
| BS002 | error | A restriction code that isn't `BAD_CREDENTIALS` with `RESTART` (the user fixes it in the app or at a URL, then the bridge is restarted) or `OPEN_NATIVE` (the bridge recovers by itself once the user fixes it in the app). Which of the two is right depends on the bridge, so there's no autofix. A restriction code contains one of these whole words (the code is split on anything that isn't a letter or digit): ban(ned), suspend(ed), suspension, restrict(ed), restriction, lock(ed), lockout, checkpoint, consent, challenge, disabled, deactivate(d), or the pairs access-denied, not-offered. |
| BS003 | error | `Message` built from `err.Error()` or `fmt.Sprintf(..., err)`. Warning when the code has a `BridgeStateHumanErrors` entry, since the text is then silently discarded. |
| BS004 | error | An error state with no `Error` code, a code that doesn't match `<error_prefix>-<reason>`, or a code built with `fmt.Sprintf`. |
| BS005 | warning | A code with no `Message` and no `BridgeStateHumanErrors` entry anywhere in the linted packages. |
| BS009 | warning | An event-handler type switch for a configured library with no case for its disconnect events. The switch is recognised by its case types being named like events, a name heuristic. |
| BS010 | warning | `TRANSIENT_DISCONNECT` reached under a check for a rejected session: a comparison against 401 or 403 (`http.StatusUnauthorized` and friends included, since they're constants), or `errors.Is`/`errors.As` against one of the `auth_errors`. |
| BS011 | warning | `BAD_CREDENTIALS` for every connect error: in a `default`/`else` branch whose condition tests an error without checking for a rejected session, or directly under `if err != nil` on a network call. |

### Login and provisioning (LP)

Login methods are the methods of `LoginProcess*` implementations plus `NetworkConnector.CreateLogin`.
Provisioning methods are `ResolveIdentifier`, `CreateGroup`, `CreateChatWithGhost`, `SearchUsers` and
`GetContactList`. A plain error from these becomes a bare 500 `M_UNKNOWN`.

Clients retry 429 and 502-504 automatically, and login and provisioning requests must not be retried
behind the user's back, so `RespError`s never use those statuses. Rate limits are `M_LIMIT_EXCEEDED` with
400, and upstream failures are 500. A chain that calls `WithCanRetry(true)` (direct media waiting on a
phone, for example) asks for retries deliberately and isn't reported.

| Rule | Severity | Flags |
|---|---|---|
| LP001 | error | A login or provisioning method returns a network error instead of a `bridgev2.RespError`, or `CreateLogin` returns a plain error directly in the `default` of a `switch` on the flow ID or in an `if` on it. Other plain errors aren't reported: nothing distinguishes bad input from an internal invariant. |
| LP002 | error | A `RespError` with status 429, 502, 503 or 504, including `mautrix.MLimitExceeded` without `WithStatus` (429 by default). Autofix sets 400 when the code is `M_LIMIT_EXCEEDED`. |
| LP004 | warning | A `RespError` status copied from a network error code (`StatusCode: te.Code`). |
| LP005 | warning | A `RespError` literal without `StatusCode`, which is sent as 500. |
| LP007 | info | A `RespError` literal for a standard Matrix code; use `mautrix.MLimitExceeded.WithMessage(...)` and friends so the status can't drift from the code. Autofix rewrites it. |
| LP008 | info | A login method re-checks a submitted field against the same regex as the field's `Pattern`. |

### Error plumbing (EP)

| Rule | Severity | Flags |
|---|---|---|
| EP001 | error | Errors matched by exact string: `err.Error() == "..."`, `switch err.Error()`, `strings.EqualFold(err.Error(), ...)`. Comparisons with `""` and substring matches aren't flagged, since some servers only give text. |
| EP002 | warning | In library packages (ones that don't import bridgev2), an `http.Response` status formatted into a plain error, so callers can't tell 429 from 403 from 5xx. |
| EP003 | info | `errors.Join` returned from a Matrix handler or used as a user-facing message. |

### General reliability (GR)

| Rule | Severity | Flags |
|---|---|---|
| GR001 | warning | An `*http.Response` whose body is never closed and isn't passed on. |
| GR002 | warning | `http.Get`/`Post`/`Head`, `http.NewRequest` without a context, or `http.DefaultClient`. |
| GR003 | warning | A request built once with a body and re-sent with `Do` inside a loop; the body is empty on retries. |
| GR004 | error | `os.Exit`, `log.Fatal*` or zerolog `Fatal()` outside `main`, `init` and `Must*` functions. Panics, including `log.Panic*` and zerolog `Panic()`, aren't flagged: they're alerted on and fixed at the source. |
| GR007 | warning | A blocking channel send in a Matrix handler (no `select` with `default` or `ctx.Done()`). |
| GR008 | warning | A cursor/seq/checkpoint field assigned after a loop that calls `QueueRemoteEvent`, before the events are handled. The field is recognised by name, a name heuristic. |
| GR009 | warning | A package-level map or slice written at runtime in a bridge package, shared by every login. |
| GR011 | warning | `GetCapabilities` changes `RoomFeatures` fields but never the `ID`, so clients cache the wrong features. |
| GR013 | warning | `LogoutRemote` that never disconnects or stops the client, when the pinned mautrix doesn't disconnect after `LogoutRemote` itself (v0.32.0 and earlier). The stopping call is recognised by name, a name heuristic. |

### Deliberately not included

These were considered and left out because they can't be checked without false positives:

- Permanent rejections recognised from error text ("not supported", "too large"): wording varies and
  doesn't say whether the author meant it to be retriable.
- Giving up after `TRANSIENT_DISCONNECT` with nothing scheduling a reconnect: whether something retries
  isn't visible without guessing from function names.
- Failures that are only logged in a background loop ("dead but green"): whether a loop is a
  connection loop or batch work, and whether something else reports the failure, isn't visible
  statically.
- Map fields that only grow, retry counters that never reset, unchecked indexing of protocol data
  (`nilaway` covers part of it) and unlocked metadata maps (run tests with `-race`).
- Missing certainty on failures returned before the network call.
- Errors in provisioning methods that are logged and not returned: these are usually best-effort steps
  after the main action has succeeded (saving the portal or setting an avatar after a group was created),
  where returning an error would make the client retry something that already happened.
- `UNKNOWN_ERROR` for an unclassified connect error: the framework already reconnects after
  `UNKNOWN_ERROR`, and libraries often classify and retry connect errors themselves (whatsmeow does with
  `InitialAutoReconnect`), which isn't visible from the bridge.
- A golangci-lint plugin. The analyzers in `rules` are plain `go/analysis` analyzers, so wiring one up
  is mostly boilerplate, but they're built for one package per process: the per-package AST parent map
  is cached for the life of the process and never evicted.

## Development

```sh
go test ./bridgelint/...
```

Tests use `analysistest` against small stub copies of the bridgev2 API under `rules/testdata/src`.
Each rule has positive cases (`// want`) next to the house pattern that should pass.
