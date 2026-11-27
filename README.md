# beeper/pre-commit-go

Beeper's pre-commit hooks for Go

| Hook | What it does |
|---|---|
| `zerolog-ban-msgf` | Ban use of `Msgf()` in zerolog |
| `zerolog-use-stringer` | Use `Stringer(x, y)` instead of `Str(x, y.String())` |
| `prevent-literal-http-methods` | Use `http.Method*` instead of literal method strings |
| `zerolog-ban-global-log` | Ban the global `github.com/rs/zerolog/log` logger |
| `ban-confusing-precedence` | Require parentheses when mixing `&&` with `\|\|`, different bitwise operators, bitwise with arithmetic, or `&` with shifts. Ignore a line with `// allow-confusing-precedence` |
| `json-use-omitzero` | Use `omitzero` instead of `omitempty` for numeric and boolean JSON fields (`omitempty` doesn't omit them in `encoding/json/v2`). Fixes tags in place |
| `bridgelint` | Check mautrix bridgev2 bridges for error-reporting and reliability mistakes, see [bridgelint/README.md](bridgelint/README.md) |
