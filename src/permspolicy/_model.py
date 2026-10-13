"""The typed policy model: an Allowlist per feature, gathered in a read-only Policy."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._errors import PermissionsPolicyError
from ._origin import parse_origin
from ._source import is_source_expression, source_matches


@dataclass(frozen=True)
class Allowlist:
    """The origins a feature is allowed in.

    ``wildcard`` is the special value ``*`` (every origin) and excludes the other fields.
    Otherwise the allowlist holds ``includes_self`` (the document's own origin),
    ``includes_src`` (the iframe ``src`` origin, only in the ``allow`` attribute) and
    ``expressions``, the source expressions in order and without repeats. An allowlist
    with none of them disables the feature.
    """

    wildcard: bool = False
    includes_self: bool = False
    includes_src: bool = False
    expressions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        flags = (self.wildcard, self.includes_self, self.includes_src)
        if any(not isinstance(flag, bool) for flag in flags):
            raise TypeError("wildcard, includes_self and includes_src are bool")
        if not isinstance(self.expressions, tuple):
            raise TypeError("expressions is a tuple of str")
        for expression in self.expressions:
            if not is_source_expression(expression):
                raise PermissionsPolicyError(f"{expression!r} is not a source expression")
        if len(set(self.expressions)) != len(self.expressions):
            raise PermissionsPolicyError("expressions repeat an entry")
        if self.wildcard and (self.includes_self or self.includes_src or self.expressions):
            raise PermissionsPolicyError("'*' cannot be combined with other entries")

    @classmethod
    def everyone(cls) -> Allowlist:
        """The allowlist ``*``: every origin."""
        return cls(wildcard=True)

    @classmethod
    def nobody(cls) -> Allowlist:
        """The empty allowlist ``()``: the feature is disabled."""
        return cls()

    @classmethod
    def of(cls, *entries: str) -> Allowlist:
        """Build from entries: ``"*"``, ``"self"``, ``"src"`` or source expressions.

        Repeated expressions are kept once. ``"*"`` cannot be mixed with other entries,
        and quoted keywords such as ``"'self'"`` are refused (write ``"self"``).
        """
        flags = {"*": False, "self": False, "src": False}
        expressions: list[str] = []
        for entry in entries:
            if not isinstance(entry, str):
                raise TypeError(f"an allowlist entry is a str, got {entry!r}")
            if entry in flags:
                flags[entry] = True
            elif not is_source_expression(entry):
                raise PermissionsPolicyError(f"{entry!r} is not '*', 'self', 'src' or a source")
            elif entry not in expressions:
                expressions.append(entry)
        return cls(flags["*"], flags["self"], flags["src"], tuple(expressions))

    @property
    def disabled(self) -> bool:
        """True when no origin at all is allowed."""
        return not (self.wildcard or self.includes_self or self.includes_src or self.expressions)

    def entries(self) -> tuple[str, ...]:
        """The allowlist as plain entries, the form :meth:`of` reads back."""
        if self.wildcard:
            return ("*",)
        keywords = ("self",) * self.includes_self + ("src",) * self.includes_src
        return keywords + self.expressions

    def allows(
        self, origin: str, *, self_origin: str | None = None, src_origin: str | None = None
    ) -> bool:
        """Run the spec "matches" algorithm for ``origin`` (an origin or any URL).

        ``self_origin`` is the origin of the document holding the policy and
        ``src_origin`` the origin of the iframe ``src``; each counts only when the
        allowlist includes it. An origin that is opaque or does not parse never matches,
        except through ``*``.
        """
        if self.wildcard:
            return True
        target = parse_origin(origin)
        if target is None:
            return False
        if self.includes_self and self_origin is not None and parse_origin(self_origin) == target:
            return True
        if self.includes_src and src_origin is not None and parse_origin(src_origin) == target:
            return True
        return any(source_matches(expression, target) for expression in self.expressions)


AllowlistLike = Allowlist | str | Iterable[str]


def to_allowlist(value: AllowlistLike) -> Allowlist:
    """Read an Allowlist, a single entry or an iterable of entries."""
    if isinstance(value, Allowlist):
        return value
    if isinstance(value, str):
        return Allowlist.of(value)
    if isinstance(value, Iterable):
        return Allowlist.of(*value)
    raise TypeError(f"an allowlist is an Allowlist or entries, got {value!r}")


class Policy(Mapping[str, Allowlist]):
    """A read-only mapping of feature name to :class:`Allowlist`, in declaration order.

    ``report_to`` maps a feature to the reporting endpoint named by its ``report-to``
    parameter. Two policies are equal when both mappings are.
    """

    __slots__ = ("_features", "_report_to")

    def __init__(
        self,
        features: Mapping[str, AllowlistLike] | None = None,
        report_to: Mapping[str, str] | None = None,
    ) -> None:
        checked: dict[str, Allowlist] = {}
        for name, value in (features or {}).items():
            if not isinstance(name, str):
                raise TypeError(f"a feature name is a str, got {name!r}")
            checked[name] = to_allowlist(value)
        endpoints = dict(report_to or {})
        for name, endpoint in endpoints.items():
            if name not in checked or not isinstance(endpoint, str):
                raise PermissionsPolicyError(f"report-to for {name!r} needs the feature and a str")
        self._features = MappingProxyType(checked)
        self._report_to = MappingProxyType(endpoints)

    @property
    def report_to(self) -> Mapping[str, str]:
        """Feature name to reporting endpoint, for the features that name one."""
        return self._report_to

    def __getitem__(self, name: str) -> Allowlist:
        return self._features[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._features)

    def __len__(self) -> int:
        return len(self._features)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Policy):
            return NotImplemented
        return dict(self._features) == dict(other._features) and dict(self._report_to) == dict(
            other._report_to
        )

    __hash__ = None  # type: ignore[assignment]

    def __repr__(self) -> str:
        extra = f", report_to={dict(self._report_to)!r}" if self._report_to else ""
        return f"Policy({dict(self._features)!r}{extra})"

    def unknown(self, known: Iterable[str] | None = None) -> tuple[str, ...]:
        """Feature names not in ``known`` (default: the features list), in order."""
        from ._features import KNOWN_FEATURES

        names = KNOWN_FEATURES if known is None else frozenset(known)
        return tuple(name for name in self._features if name not in names)
