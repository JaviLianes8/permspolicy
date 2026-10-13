# permspolicy

Parse, build and check the HTTP `Permissions-Policy` header, the iframe `allow` attribute
and the legacy `Feature-Policy` header, with a typed, zero-dependency API.

## Install

```
pip install permspolicy
```

## Usage

Read a header the way a browser does, and ask what it allows:

```python
from permspolicy import parse

policy = parse('geolocation=(self "https://*.maps.example"), camera=(), fullscreen=*')
print(list(policy))
# ['geolocation', 'camera', 'fullscreen']
print(policy["geolocation"].entries())
# ('self', 'https://*.maps.example')
print(policy["camera"].disabled)
# True
print(policy["geolocation"].allows("https://tiles.maps.example"))
# True
print(policy["geolocation"].allows("https://shop.example", self_origin="https://shop.example"))
# True
```

The field is a structured field Dictionary (RFC 9651). A value that does not parse is
ignored as a whole, as browsers ignore it, and entries the spec drops are dropped.
`strict=True` raises instead, with the offset of the problem:

```python
from permspolicy import PermissionsPolicyError, parse

print(parse('geolocation=(self), camera=("https://a.example" , self)'))
# Policy({})
try:
    parse("geolocation=(self), camera=(self", strict=True)
except PermissionsPolicyError as error:
    print(error.offset)
# 32
print(parse("geolocation=(self);report-to=main").report_to)
# {'geolocation': 'main'}
```

Build one from plain entries (`"*"`, `"self"` or source expressions) or from `Allowlist`
values. Anything that would not read back the same way raises, so untrusted input
cannot add a header line or another member:

```python
from permspolicy import Allowlist, PermissionsPolicyError, Policy, build

print(build({"geolocation": ["self", "https://a.example"], "camera": [], "fullscreen": "*"}))
# geolocation=(self "https://a.example"), camera=(), fullscreen=*
print(build(Policy({"usb": Allowlist.nobody()}, report_to={"usb": "main"})))
# usb=();report-to=main
try:
    build({"camera": ["https://a.example\r\nSet-Cookie: x=1"]})
except PermissionsPolicyError as error:
    print("refused")
# refused
```

The iframe `allow` attribute and the legacy `Feature-Policy` header share an older
syntax. Read it, write it, or convert it to the header:

```python
from permspolicy import build, build_allow, parse_allow, parse_feature_policy

frame = parse_allow("camera; geolocation 'self' https://maps.example/embed")
print(frame["camera"].entries(), frame["geolocation"].entries())
# ('src',) ('self', 'https://maps.example')
print(build_allow({"microphone": [], "fullscreen": "*"}))
# microphone 'none'; fullscreen *
print(build(parse_feature_policy("geolocation 'self'; camera 'none'")))
# geolocation=(self), camera=()
```

Check feature names against the features list kept with the spec:

```python
from permspolicy import RETIRED_FEATURES, parse

policy = parse("camera=(), geolocaton=(), document-domain=()")
print(policy.unknown())
# ('geolocaton', 'document-domain')
print("document-domain" in RETIRED_FEATURES)
# True
```

## Command line

```
$ permspolicy 'geolocation=(self), camera=()' --origin https://a.example --self-origin https://a.example
{
  "features": {
    "geolocation": {
      "allowlist": [
        "self"
      ],
      "allows_origin": true
    },
    "camera": {
      "allowlist": [],
      "allows_origin": false
    }
  },
  "unknown": []
}
$ permspolicy --feature-policy --to-header "geolocation 'self' https://a.example"
geolocation=(self "https://a.example")
```

The value can also come from standard input. `--allow` and `--feature-policy` read the
older syntax, `--to-header` and `--to-allow` convert, `--strict` exits 1 on a value the
spec would ignore, and `--check` exits 1 when a feature name is not in the features list.

## API

| Name | What it does |
| --- | --- |
| `parse(header, *, strict=False)` | Read a `Permissions-Policy` (or `-Report-Only`) value, bytes or field lines into a `Policy`. |
| `build(policy)` | Serialize a `Policy` or a mapping of entries; refuses anything that would not read back. |
| `parse_allow(value, *, strict=False)` | Read an iframe `allow` attribute. |
| `build_allow(policy)` | Write an iframe `allow` attribute. |
| `parse_feature_policy(value, *, strict=False)` | Read a legacy `Feature-Policy` value. |
| `build_feature_policy(policy)` | Write a legacy `Feature-Policy` value. |
| `Policy` | Read-only mapping of feature to `Allowlist`, with `report_to` and `unknown()`. |
| `Allowlist` | Frozen allowlist: `wildcard`, `includes_self`, `includes_src`, `expressions`, `allows()`. |
| `serialize_origin(url)` | The origin of a URL (`https://a.example:8443`), or None when it is opaque. |
| `is_source_expression(text)` | True for an entry the header accepts (`https:`, `*.a.example`, an origin). |
| `KNOWN_FEATURES` | Every standardized, proposed and experimental feature name. |
| `STANDARDIZED_FEATURES`, `PROPOSED_FEATURES`, `EXPERIMENTAL_FEATURES`, `RETIRED_FEATURES` | The features list by status. |
| `PermissionsPolicyError` | A `ValueError` for invalid policies and strict parse failures, with `offset`. |

## Limits

- Origins are computed for http, https, ws, wss and ftp (and `blob:` URLs over http or
  https). Other schemes have opaque origins and are dropped, as browsers drop them.
  Non-ASCII hosts, IPv6 literals and short IPv4 forms are refused rather than normalized.
- Feature names are not filtered when parsing: a browser ignores names it does not know,
  and which names it knows depends on the browser. `Policy.unknown()` lists them.
- Inheritance through frames and the default allowlist of each feature need a browsing
  context and are out of scope.

## Why

Permissions-Policy builders already exist, but they are write-only and tied to a
framework, and none reads a header back the way a browser does. permspolicy parses on
the structured field grammar, builds only what parses back, answers whether an origin is
allowed, and handles the `allow` attribute and the legacy header too.

## Reference files

The tests check the code against the Permissions Policy spec, its features list, CSP3 and
the httpwg structured field tests. Those files are not part of the repository;
`python scripts/fetch_upstream.py` fetches them into `tests/upstream/` and checks them
against `tests/upstream/MANIFEST.json`. Without them, the tests that read them skip.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
