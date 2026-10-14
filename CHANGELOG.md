# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Changed

- `parse` reads the field as an RFC 9651 Dictionary. A value that does not parse is ignored
  as a whole (an empty `Policy`), as browsers do; before, the readable part was kept.
  Inside a valid value, inner list items the spec ignores are dropped, and a member of any
  other form declares the feature with an empty allowlist, as the spec algorithm does.
- `parse` returns a `Policy` (a read-only mapping of feature to `Allowlist`) instead of a
  dict of string lists. `Allowlist.entries()` gives the old list form.
- `build` accepts only `*`, `self` and source expressions, lower-case feature names and
  Token endpoints; anything else raises, so the output cannot carry a line break or an
  extra member. A quoted `'self'` is refused instead of being written as an origin.

### Added

- `strict=True` on every parser raises `PermissionsPolicyError` (now with `offset`) for
  what the lenient mode ignores.
- Several field lines and `bytes` input; the `report-to` parameter, read and written.
- `Allowlist` with `allows()`, the spec "matches" algorithm with the CSP3 scheme, host,
  port and path rules; `serialize_origin` and `is_source_expression`.
- `parse_allow`, `build_allow`, `parse_feature_policy` and `build_feature_policy` for the
  iframe `allow` attribute and the legacy `Feature-Policy` header.
- The features list by status (`KNOWN_FEATURES` and four status sets) and
  `Policy.unknown()`.
- A `permspolicy` command line (also `python -m permspolicy`).
- Tests against the pinned spec, features list, CSP3 and the httpwg structured field tests,
  fetched by `scripts/fetch_upstream.py` and never committed.

## [0.1.0]

- `parse` reads a Permissions-Policy header into `{feature: allowlist}`, handling `*`, `()`,
  the `self` token and quoted origins, and tolerating malformed members.
- `build` serializes a mapping back into a header with correct quoting and validation.
- `PermissionsPolicyError` for invalid feature names and misplaced `*`.
