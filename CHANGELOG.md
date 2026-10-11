# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

- `parse` reads a Permissions-Policy header into `{feature: allowlist}`, handling `*`, `()`,
  the `self` token and quoted origins, and tolerating malformed members.
- `build` serializes a mapping back into a header with correct quoting and validation.
- `PermissionsPolicyError` for invalid feature names and misplaced `*`.
