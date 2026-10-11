# permspolicy

Parse and build the HTTP Permissions-Policy header with a typed, zero-dependency API.

## Install

```
pip install permspolicy
```

## Usage

```python
from permspolicy import build, parse

header = parse('geolocation=(self "https://a.example"), camera=(), fullscreen=*')
# {'geolocation': ['self', 'https://a.example'], 'camera': [], 'fullscreen': ['*']}

build({"geolocation": ["self", "https://a.example"], "camera": [], "fullscreen": ["*"]})
# 'geolocation=(self "https://a.example"), camera=(), fullscreen=*'
```

An allowlist is a plain list of tokens and origins:

- `["*"]` serializes to `*` and means any origin.
- `[]` serializes to `()` and disables the feature.
- `["self", "https://a.example"]` keeps `self` as a bare token and quotes each origin.

`parse` is tolerant: it skips members it cannot read rather than raising, so a partial
header still yields whatever is well formed. `build` raises `PermissionsPolicyError` on an
invalid feature name or when `*` is mixed with other entries.

## Why

Permissions-Policy builders already exist, but every one is write-only and tied to a
framework: `secure.py`, `django-permissions-policy` and `apifrom` all emit the header and
none reads an incoming one back into a structure. There was no small, typed, zero-dependency
library that both parses and builds the header. permspolicy fills that gap with a single
round-tripping pair of functions.

## License

MIT. See [LICENSE](LICENSE).

## Links

- Website: https://lianes8studio.com
- GitHub: https://github.com/JaviLianes8
- LinkedIn: https://www.linkedin.com/in/jlianes/
