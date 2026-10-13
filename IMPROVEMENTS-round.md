# permspolicy improvement round

Progress:
- [x] Brainstorm ranked improvements (this file)
- [ ] Pin the ground truth: Permissions Policy spec, features registry, CSP source grammar, RFC 9651, structured field test corpus
- [ ] Structured field dictionary parser and serializer on RFC 9651, checked against the corpus
- [ ] Header parsing on the whole field: failure ignores the header, strict mode raises
- [ ] Typed model: Allowlist and Policy, report-to, origin matching
- [ ] Safe builder that cannot inject
- [ ] iframe allow attribute and legacy Feature-Policy: parse, build, convert
- [ ] Features registry
- [ ] Command line
- [ ] Contracts: pinned sources, README examples, typing, installed wheel
- [ ] Docs and packaging: README, CHANGELOG, metadata, sdist contents
- [ ] Gates: ruff format, ruff check, mypy --strict, pytest
- [ ] Mutation run: removing guarded logic makes the suite fail
- [ ] Independent review findings fixed with regression tests
- [ ] Pull request opened, guard clean

## Starting point

`0.1.0` gives `parse`, `build` and `PermissionsPolicyError`. `parse` splits the text by
hand and keeps whatever it can read; `build` quotes every entry. Probed:

- A header that is not a valid Dictionary is still read: `geolocation=(self), @@@` keeps
  `geolocation`. The spec reads the field with RFC 9651 "get a structured field value",
  and a field that fails to parse is ignored as a whole.
- Invalid items leak into allowlists: `camera=("x" 1 ?1)` gives `['x', '1', '?1']`,
  `a=(self` gives `['(self']`, `camera=("https://a.example" , self)` keeps the `,`.
- Upper-case keys (`Geo=()`) are accepted although Dictionary keys are lower case.
- Parameters are not understood: `geolocation=self;report-to=ep` yields the allowlist
  `['self;report-to=ep']`. The `report-to` parameter is lost.
- Several field lines cannot be passed; a CR LF inside the text is read as data.
- `build` writes CR LF straight into the header (`"https://a.example\r\nSet-Cookie: a"`),
  so a caller that passes untrusted origins can inject header lines. It also writes a
  quoted `"'self'"` (a legacy keyword) as if it were an origin.
- No typed model (a list of strings mixes keywords and origins), no origin matching, no
  support for the iframe `allow` attribute or the legacy `Feature-Policy` header, no
  features list, no command line, README examples are not run.

## Sources (fetched 2026-10-13)

- Permissions Policy, editor's draft source `index.bs` at w3c/webappsec-permissions-policy
  commit 29398046f1e0cb45c091adda853df74925dc740a: allowlists, the HTML attribute
  serialization (ASCII grammar), the structured header serialization, the header field,
  "Construct policy from dictionary and origin", "Parse policy directive", the `allow`
  and `allowfullscreen` attributes, "matches".
- Policy-controlled features list, `features.md` at the same commit.
- CSP3, `index.bs` at w3c/webappsec-csp commit b1bad631b091cdca904138d6947a16b89edfd2b4:
  `scheme-source` and `host-source` grammar and the matching algorithms the Permissions
  Policy "matches" algorithm calls.
- RFC 9651, https://www.rfc-editor.org/rfc/rfc9651.txt.
- Structured field test corpus, httpwg/structured-field-tests at commit
  781ba38464b2ec4c547e1e14d007d4f5ace7457e.
- None of these files is committed. `tests/upstream/MANIFEST.json` records URL, revision,
  size, sha256 and licence; `scripts/fetch_upstream.py` fetches them into the ignored
  `tests/upstream/` folder, and the tests that read them skip while they are absent.

## Ranked improvements

1. **Correct receiver semantics.** Parse the whole field as an RFC 9651 Dictionary. A field
   that fails gives an empty policy (lenient, as browsers do) or raises with an offset
   (`strict=True`). Inside a valid field, members follow the spec: `*` anywhere means every
   origin, `self` sets the self flag, Strings that are valid source expressions are kept,
   other inner list items are dropped, and other member values drop the member. Several
   field lines are joined with a comma; `bytes` are read as ASCII.
2. **Typed model.** A frozen `Allowlist` (any origin, self, src, expressions) and a
   read-only `Policy` mapping with the `report-to` endpoints, instead of lists of strings.
3. **Builder that cannot inject.** Feature names must be Dictionary keys, entries must be
   `*`, `self` or a valid source expression, `report-to` must be a Token. Anything else
   raises, so the output always parses back to the same policy.
4. **Origin matching.** `Allowlist.allows(origin, self_origin=..., src_origin=...)` runs the
   spec "matches" algorithm with the CSP scheme, host, port and path rules.
5. **iframe `allow` and legacy `Feature-Policy`.** Parse with the "Parse policy directive"
   steps (split on `;`, then on ASCII whitespace, case-insensitive `'self'` and `'src'`,
   URLs reduced to their origin), build the ASCII form, and convert either way.
6. **Features registry.** The names from the features list by status (standardized,
   proposed, experimental, retired), checked against the pinned file.
7. **Command line.** `permspolicy VALUE` prints the policy as JSON; `--allow` and
   `--feature-policy` read the other syntaxes, `--to-header` converts, `--check` lists
   unknown features, `--strict` exits 1 on a value that does not parse.
8. **Contracts.** Spec grammar and examples read from the pinned files, the corpus run
   against the codec, README examples executed, public types checked with mypy, the
   installed wheel and its console script driven from an empty folder.
9. **Docs and packaging.** README with executed examples and an API table, CHANGELOG,
   keywords and classifiers, sdist without planning notes or fetched files.

## Out of scope

- Full WHATWG URL parsing. Origins are read for the special schemes (http, https, ws, wss,
  ftp); other schemes have opaque origins and are dropped, as the spec does. IPv4 short
  forms and non-ASCII hosts are refused instead of normalized.
- Inheritance through frames and default allowlists: they need browsing context state.
- Document Policy, a separate header with a different model.
