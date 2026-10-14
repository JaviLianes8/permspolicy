"""Policy-controlled feature names, from the features list of the Permissions Policy repo.

Source: https://github.com/w3c/webappsec-permissions-policy/blob/main/features.md at commit
29398046f1e0cb45c091adda853df74925dc740a (fetched 2026-10-13). Browsers ignore names they do
not know, so the list is a lint aid, not a filter.
"""

from __future__ import annotations

STANDARDIZED_FEATURES: frozenset[str] = frozenset(
    {
        "accelerometer",
        "ambient-light-sensor",
        "attribution-reporting",
        "autoplay",
        "battery",
        "bluetooth",
        "camera",
        "ch-ua",
        "ch-ua-arch",
        "ch-ua-bitness",
        "ch-ua-full-version",
        "ch-ua-full-version-list",
        "ch-ua-high-entropy-values",
        "ch-ua-mobile",
        "ch-ua-model",
        "ch-ua-platform",
        "ch-ua-platform-version",
        "ch-ua-wow64",
        "compute-pressure",
        "cross-origin-isolated",
        "direct-sockets",
        "display-capture",
        "encrypted-media",
        "execution-while-not-rendered",
        "execution-while-out-of-viewport",
        "fullscreen",
        "geolocation",
        "gyroscope",
        "hid",
        "identity-credentials-get",
        "idle-detection",
        "keyboard-map",
        "magnetometer",
        "mediasession",
        "microphone",
        "midi",
        "navigation-override",
        "otp-credentials",
        "payment",
        "picture-in-picture",
        "publickey-credentials-get",
        "screen-wake-lock",
        "serial",
        "sync-xhr",
        "storage-access",
        "tools",
        "usb",
        "web-share",
        "window-management",
        "xr-spatial-tracking",
    }
)
"""Features defined in a published specification."""

PROPOSED_FEATURES: frozenset[str] = frozenset(
    {
        "autofill",
        "clipboard-read",
        "clipboard-write",
        "deferred-fetch",
        "gamepad",
        "language-detector",
        "language-model",
        "manual-text",
        "rewriter",
        "speaker-selection",
        "summarizer",
        "translator",
        "writer",
    }
)
"""Features proposed for a specification but not yet in one."""

EXPERIMENTAL_FEATURES: frozenset[str] = frozenset(
    {
        "all-screens-capture",
        "browsing-topics",
        "captured-surface-control",
        "conversion-measurement",
        "digital-credentials-create",
        "digital-credentials-get",
        "focus-without-user-activation",
        "join-ad-interest-group",
        "local-fonts",
        "monetization",
        "run-ad-auction",
        "smart-card",
        "sync-script",
        "trust-token-redemption",
        "unload",
        "vertical-scroll",
    }
)
"""Features some browser experiments with, without a specification."""

RETIRED_FEATURES: frozenset[str] = frozenset(
    {
        "document-domain",
        "window-placement",
    }
)
"""Features browsers have dropped or renamed."""

KNOWN_FEATURES: frozenset[str] = STANDARDIZED_FEATURES | PROPOSED_FEATURES | EXPERIMENTAL_FEATURES
"""Every feature that is standardized, proposed or experimental (not retired)."""
