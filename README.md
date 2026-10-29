# beeper/pre-commit-go

Beeper's pre-commit hooks for Go

| Hook | What it does |
|---|---|
| `zerolog-ban-msgf` | Ban use of `Msgf()` in zerolog |
| `zerolog-use-stringer` | Use `Stringer(x, y)` instead of `Str(x, y.String())` |
| `prevent-literal-http-methods` | Use `http.Method*` instead of literal method strings |
| `zerolog-ban-global-log` | Ban the global `github.com/rs/zerolog/log` logger |
| `bridgelint` | Check mautrix bridgev2 bridges for error-reporting and reliability mistakes, see [bridgelint/README.md](bridgelint/README.md) |
