# Task 3: LLM gateway streaming guardrail (PII redaction)

An OpenAI-compatible gateway endpoint (`POST /v1/chat/completions`) that
routes text-generation requests to Anthropic and **streams the response back
with emails, SSNs and credit-card numbers replaced by `[REDACTED]`, in real
time, without accumulating the response.**

```
client ──OpenAI-style request──► gateway ──Anthropic SDK (stream)──► Claude
   ◄── chat.completion.chunk SSE ── StreamRedactor ◄── text deltas ──┘
```

## Requirements → implementation

| Requirement (ASSESSMENT.md) | Where | Proven by |
|---|---|---|
| Proxy endpoint that routes generation requests to an LLM provider and streams the response back | `api.py` (OpenAI-compatible SSE) + `providers.py` (Anthropic SDK, `stream=True`) | `test_api.py`, `test_redaction_e2e.py` (real sockets, real SDK against a mock Anthropic API) |
| Intercept the chunk stream in real time; parse deltas | `providers.py` yields only `text_delta` text; `api.py` feeds each delta to the redactor | `test_pii_split_across_real_sdk_stream_chunks_is_redacted` |
| Detect and redact emails, SSNs, credit-card numbers → `[REDACTED]` | `redactor.py` (Luhn-checked cards, never-issued SSN ranges excluded) | `test_redactor.py` |
| Stay responsive; no full-response accumulation; minimal TTFT and latency | Bounded hold-back (current word, ≤ 2048 chars), commit on first event, linear-time scanning | Property test, TTFT test over real sockets, memory and timing tests |

## Run it

```bash
uv sync
export ANTHROPIC_API_KEY=...                         # read by the Anthropic SDK
export CLIENT_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
LLM_GATEWAY_API_KEYS="[\"$CLIENT_KEY\"]" uv run python -m task3_pii_guardrail   # :8090

curl -N http://127.0.0.1:8090/v1/chat/completions \
  -H "authorization: Bearer $CLIENT_KEY" -H 'content-type: application/json' \
  -d '{"model":"claude-opus-5-5","stream":true,"messages":[{"role":"user","content":"Hi"}]}'
```

Any OpenAI SDK works by pointing `base_url` at `http://127.0.0.1:8090/v1`.
Offline: `python -m task3_pii_guardrail.mock_provider --port 9090` plus
`LLM_GATEWAY_ANTHROPIC_BASE_URL=http://127.0.0.1:9090`.

### A real session (mock provider; it echoes the prompt in 3-character deltas)

```text
→ "mail jane.doe@example.com, ssn 123-45-6789, card 4111 1111 1111 1111 thanks"   (stream: true)
← data: {"object":"chat.completion.chunk",…,"delta":{"role":"assistant","content":""}}
← data: {"object":"chat.completion.chunk",…,"delta":{"content":"You "}}
← …
reassembled: "You said: mail [REDACTED], ssn [REDACTED], card [REDACTED] thanks"

→ "reach me at a@b.io" (stream: false)   ← {"role":"assistant","content":"You said: reach me at [REDACTED]"}
→ provider returns 429                   ← HTTP 429, Retry-After: 3, {"error":{"type":"rate_limit_error",…}}

gateway audit:  llm.response_redaction redact | 3 sensitive value(s) redacted from the model response
PII occurrences in the gateway's own log:  0
```

**Measured cost:** the redactor takes **0.67 µs per chunk**: a 61 KB stream in
15,700 token-sized chunks (≈ 4 chars) took 10.6 ms in total. Model tokens
arrive tens of milliseconds apart, so the guardrail adds no noticeable
latency.

## Design, and why

### The streaming redactor (`redactor.py`)

**The problem.** A value can be split across deltas (`"jane@exa"` +
`"mple.com"`). Redacting each chunk on its own misses it. Buffering the
whole response defeats streaming.

**The approach: hold back only what could still become a match.** Every
pattern matches a contiguous run of *candidate characters*: ASCII letters,
digits and `._%+@-`, plus a space only *between digits* (card and SSN
separators). So at any moment only the **trailing run** of candidate
characters can still grow into a match. Everything before it ends at a
boundary no match can cross, so it is redacted and emitted immediately.

| Property | How it's achieved | Evidence |
|---|---|---|
| **Correct for any chunking** | The cut is always at a boundary, and the patterns use `re.ASCII`, so `\b` and lookarounds evaluate the same as on the whole text | Property test: any chunking gives the same output as `redact_all(whole_text)`; a 20,000-case random stress run (incl. non-ASCII) matched 20000/20000 |
| **Low latency** | In prose the held text is just the current word: `"The quick "` leaves at once, while `"jum"` waits for its boundary | `test_prose_is_released_as_soon_as_each_word_ends`; TTFT test over real sockets |
| **Bounded memory** | Hold-back capped at **2048 chars**. Longer unbroken runs (base64 blobs) are force-emitted in 1 KB blocks. The cut is moved so it never splits a complete match, searching a window longer than the longest possible match (665 chars). The forced path can only over-redact, never leak. | 1 MB with no boundary: hold-back never exceeds the cap; a 665-char email straddling the cut is still redacted |
| **Linear cost** | `feed()` scans only the new chunk plus one held character. Each emitted region is regex-scanned once. Bounded quantifiers and anchored starts mean no quadratic re-scanning | 120 KB in 4-char chunks < 2 s; hostile inputs (`"a"*50k`, `"@"*50k`) < 1 s |

**Detection rules.**
- Emails: a practical RFC 5322 subset.
- SSNs: `ddd-dd-dddd` or space-separated, excluding never-issued ranges (`000`, `666`, `9xx`, group `00`, serial `0000`).
- Cards: 13–19 digits passing the **Luhn checksum**, either unseparated or in a real PAN layout (one separator style, groups of 3 or more digits). That avoids flagging order numbers and SSN pairs, while still catching a card followed by its CVV group.

**Content blocks are redacted independently.** A Claude response can have
several text blocks (citations, a refusal-fallback switch). They are
concatenated for the client, but each block goes through its own redactor.
Otherwise a card ending one block and a digit starting the next would merge
into one run that fails the Luhn and boundary checks.

**Mid-stream failure:** held text is **discarded, not flushed**. A held
`"jane.do"` can no longer be identified once the rest of the stream is lost,
so flushing it would leak a fragment of PII.

### The gateway (`api.py`, `providers.py`)

- **OpenAI-compatible surface.** Existing clients change only `base_url`. The
  response is `chat.completion.chunk` SSE ending in `[DONE]`, or a
  `chat.completion` when `stream: false`.
- **Commit on first event.** HTTP 200 is sent only once the provider's first
  event arrives, so failures before any output (429 with `Retry-After`,
  outage) are real HTTP errors that a client or Task 4's fallback router can
  act on. After that, each delta is forwarded as soon as the redactor marks it
  safe.
- **Provider call.** The official Anthropic SDK, low-level `stream=True` (no
  message accumulation), model `claude-opus-5-5`. Only `text_delta` text is
  forwarded. Stop reasons map to OpenAI terms (`max_tokens` → `length`,
  `refusal` → `content_filter`).
- **Refusal fallback on by default.** The request opts into Anthropic's
  server-side fallback (`fallbacks: "default"`): if the model declines on
  safety grounds, Anthropic re-runs it on a fallback model within the same
  call. Turn it off with `LLM_GATEWAY_REFUSAL_FALLBACK=false`.
- **Model selection.** The client's `model` field is required for
  compatibility, but the gateway routes to its configured model
  (`LLM_GATEWAY_MODEL`). Clients can't pick arbitrary (expensive) models.

**Error shape.** The OpenAI error envelope plus `request_id`
(`{"error":{"message","type","code","param","request_id"}}`), with
`X-Request-ID` on every response. Validation errors name the offending
`param`. Provider detail (hostnames, upstream messages) stays in the log.

| Situation | HTTP |
|---|---|
| Missing or wrong API key | 401 `authentication_error` |
| Bad JSON / schema / unknown field (e.g. `temperature`) | 400 `invalid_request_error` + `param` |
| Body over 1 MiB | 413 |
| Provider rate-limited | 429 + `Retry-After` |
| Provider down / rejected our request / timed out | 502 / 502 / 504 `provider_error` |
| Provider fails mid-stream | SSE `{"error":…}` event, then `[DONE]` |

## Security considerations

- Client API keys are compared in **constant time** against every configured
  key. Logs carry only a hashed principal id, never the key.
- **Redaction is audited without content:** each response that needed
  redaction emits an audit event with the *count*. The gateway's own logs
  contain no PII (checked in the demo and the integration test).
- Request bodies are capped, JSON is parsed strictly (no `NaN`), and unknown
  fields are rejected.
- The Anthropic key is read by the SDK from `ANTHROPIC_API_KEY` and never
  stored in settings or logs.

## Tests

```bash
uv run pytest task3-pii-guardrail -q
RUN_LIVE_TESTS=1 ANTHROPIC_API_KEY=... uv run pytest task3-pii-guardrail -m live   # real API, costs money
```

| Suite | Tests | What it proves |
|---|---|---|
| `test_redactor.py` | 44 | Every pattern; false positives avoided; every split point; char-by-char; **any chunking equals whole text (Hypothesis)**; word-level latency; bounded memory; linear and hostile-input timing; discard; exact counts |
| `test_api.py` | 36 | OpenAI chunk format; redaction across provider chunks **and content blocks**; error mapping and sanitising (incl. hostile `Retry-After`, deep nesting); mid-stream failure with discard; audit event carries request id and principal; auth incl. blank/NBSP tokens; validation with `param`; provider stream always closed |
| `test_redaction_e2e.py` | 8 (+1 live) | **Real processes and sockets through the real Anthropic SDK**: streaming and non-streaming redaction, audit count, no PII in logs, TTFT before a provider pause, 429/502 mapping, mid-stream failure, auth |

The TTFT test lives in the e2e suite on purpose: httpx's in-process
`ASGITransport` buffers whole responses, so latency can only be observed over
a real socket.

## Known limitations

- **Pattern-based detection.** It covers the three types the brief names
  (emails, US SSNs, card numbers). Names, addresses, phone numbers and
  non-US identifiers need NER/ML classifiers (QuilrAI's "custom intents").
- **ASCII matching.** Patterns use `re.ASCII` (needed for chunk-invariant
  boundaries), so full-width digits or a zero-width character inside a value
  (`jane<U+200B>@example.com`) evade detection, in whole-text and streaming
  mode alike. Normalising the text first would be the next step.
- **Length caps.** Emails with a local part over 64 characters or a domain
  label over 63 (beyond RFC limits) are not matched.
- **Truncated output.** If the model stops at `max_tokens` mid-value
  (`"jane.do"`), the fragment no longer matches and is emitted as-is, exactly
  as whole-text redaction would treat it.
- **Response path only.** PII in the *prompt* is sent to the provider
  unredacted. Request-side redaction is a separate guardrail.
- **Unbroken runs over 2048 chars** are force-emitted in blocks. That path is
  allowed to over-redact (a truncated digit run that looks like a card) so it
  can never leak.
- **Single provider, single model.** Rate limiting and fallback across
  providers are Task 4.
