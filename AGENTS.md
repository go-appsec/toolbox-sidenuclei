## Commands

- `make build` — build `./bin/sidenuclei`
- `make test` — fast tests (`go test -short ./...`)
- `make test-all` — race + cover (the pre-commit gate)
- `make lint` — `gofmt` changed files, then `golangci-lint` + `go vet` (also a pre-commit gate)

Verify a change with `make test-all` and `make lint` before considering it complete.

## Architecture

`sidenuclei` is a **sidecar** that attaches to a running [go-appsec/toolbox](https://github.com/go-appsec/toolbox) (`sectool`) session over its sidecar socket and scans the endpoints you touch with [Nuclei](https://github.com/projectdiscovery/nuclei), filing results back as `finding` notes. The scanner is self-contained: it embeds the nuclei SDK (`nuclei/v3/lib`) and auto-installs templates on first run.

Two packages:

- `sidenuclei/` (package `main`) — the sidecar: connection, poll loop, worker pool, note filing, config.
- `sidenuclei/nuclei/` (package `nuclei`) — the nuclei engine wrapper, decoupled from sectool wire types.

### Data flow (the core loop)

1. **`connect.go`** dials sectool and registers as an observer (originates nothing), declaring MCP tools specific to nuclei.
2. **`poll.go` `pullLoop`** is a `proxy_poll` cursor loop. Each tick it advances a `flow_id` cursor over new flows, drops replay traffic and already-seen endpoints (`skip` / `endpointKey`, which dedups on method+host+port+path with query *values* stripped but *parameter names* kept), builds each unique flow's scan target (`flow_get` + `BuildImportTarget`, so the body is captured before sectool can evict the flow), and `enqueue`s it onto an unbounded in-memory queue that the workers drain. The poll loop never blocks on scan throughput. Backoff is driven by `remaining_count` — drain immediately when flows remain, else `--poll-interval`.
3. **`scan.go`** worker pool pulls built targets off the queue (`dequeue`) and runs the engine under a per-endpoint timeout (`--scan-timeout`). Findings are filed under the *parent* context, not the scan context, so a scan deadline never cancels `notes_save`.
4. **`notes.go`** renders each finding into a greppable note body and files it via `notes_save`, linked to the originating `flow_id`. Deduped per (template, matched-at). Warns once if sectool was started without `--notes`.
5. **`status.go`** serves the `nuclei_status` MCP tool via `handler.OnInvokeTool`, projecting the shared `scanner`'s live counters (activity, queue depth, findings filed) and enabled coverage into structured output. Read-only; findings themselves stay in notes. The `scanner` is built in `main.run` and shared with the poll loop so both see one source of truth.

### Nuclei engine (`nuclei/`)

- **`engine.go`** — `Engine` holds two warm, reusable `passEngine`s: a **detect** pass (standard templates, `dos`/`intrusive` always excluded) and a **fuzz** pass (DAST mode, active injection payloads). `Scan` runs detect on all targets and fuzz only on `Fuzzable` ones. Each `passEngine` **serializes execute with a mutex** — the nuclei lib is not concurrency-safe per engine, so `MaxConcurrentScans > 1` parallelizes across endpoints but execute is still one-at-a-time per pass. The dispatcher callback is registered exactly once (the lib appends callbacks per execute); the live callback is swapped via an atomic pointer.
- **`rawrequest.go`** — `BuildImportTarget` assembles the raw HTTP request nuclei fuzzes: normalizes to CRLF, base64-decodes the body, and rewrites framing (drops `Transfer-Encoding`, sets real `Content-Length`).
- **`nuclei.go`** — `mapEvent` projects nuclei's `output.ResultEvent` into the trimmed `Finding` type. Keep the wire-facing `Finding` decoupled from nuclei internals here.

### Config (`config.go`)

Coverage is a set of **categories** (`category{on, tags}`), not directly-set engines. Detection categories (CVE/exposures/misconfig/tech) are on by default with `--disable-*` flags; injection fuzzing classes (sqli/xss/cmdi/...) are opt-in. `engineConfig()` projects enabled categories → nuclei tag filters. When adding a coverage flag, wire it through `detectCategories()`/`fuzzCategories()`, the `enabledDetectionNames()`/`enabledFuzzNames()` helpers (so `nuclei_status` coverage stays accurate), and (for active-injection classes) `enabledInjectionClasses()` so the startup safety warning stays accurate.

## Code Style

- Use `var` style for zero-value initialization: `var foo bool`, not `foo := false`.
- Comments are concise short phrases, not full sentences, and only where they add non-obvious context — never restating a single line of code.
- Godocs describe inputs and outputs, not how the function works.
- Follow existing naming conventions and neighboring code style.

**Collection handling** — reach for stdlib `slices`/`maps`/`strings` and `github.com/go-analyze/bulk` before a manual loop:

- Clone whole slice/map: `slices.Clone(src)` / `maps.Clone(src)` — not `make`+`copy` (`copy` is still correct for sub-slice writes into an existing buffer).
- Filter (same element type): `bulk.SliceFilter(pred, s)`, or `bulk.SliceFilterInPlace` when the input backing array isn't reused.
- Slice → set: `bulk.SliceToSet(s)` (`map[T]struct{}`), test with `if _, ok := set[k]; ok`. `bulk.SliceToSetBy` for a key func (see `sidescale/dispatch.go`).
- Map → keys/values slice: `bulk.MapKeysSlice(m)` / `bulk.MapValuesSlice(m)` — not a `for k := range m` append loop.
- Membership: `slices.Contains` (comparable) / `slices.ContainsFunc` (predicate).
- Custom sort: `slices.SortFunc` / `slices.SortStableFunc`, not `sort.Slice{,Stable}`.

## Testing

Structure and conventions:

- One `_test.go` file per implementation file that requires testing.
- One `func Test<FunctionName>` per target function, using table-driven tests or `t.Run` cases.
- Test case names are at most 3–5 words, lower case with underscores.
- `t.Parallel()` at test-function start when there's no shared state, but not in the individual cases.
- Isolated temp dirs via `t.TempDir()`; context timeouts via `t.Context()` for tests with I/O.
- Cleanup via `t.Cleanup`, not `defer`.

Assertions and validation:

- `testify`: `require` for setup, `assert` for assertions.
- No assertion messages unless the message adds context beyond the test point itself.
- Never `time.Sleep` — use `require.Eventually` or a deterministic trigger.
- Check every returned error with `require.NoError` / `assert.NoError` whenever `*testing.T` is in scope, except inside `t.Cleanup` and goroutines.
- Verify with `make test-all` and `make lint` before considering a change complete.

Testing seams:

- `CoreInvoker` (`poll.go`) abstracts `(*sidecar.Conn).CoreInvoke` so tests feed canned `proxy_poll`/`flow_get`/`notes_save` responses with no live sectool.
- `scanEngine` (`scan.go`) abstracts the nuclei engine so scan-loop tests use a fake.
