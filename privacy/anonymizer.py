"""Investigation-scoped pseudonymization and full credential redaction."""

from __future__ import annotations

import ipaddress
import re
import secrets
from collections import defaultdict
from typing import Any

from .pii_detector import (
    SensitiveMatch,
    canonical_entity,
    detect_text,
    entity_kind_for_field,
    is_pseudonym,
)


_PREFIXES = {
    "ipv4": "IP",
    "ipv6": "IP",
    "ip_address": "IP",
    "username": "USER",
    "hostname": "HOST",
    "email": "EMAIL",
    "phone_number": "PHONE",
    "mac_address": "MAC",
    "file_path": "PATH",
}
_REDACTIONS = {
    "password": "[REDACTED_PASSWORD]",
    "api_key": "[REDACTED_SECRET]",
    "access_token": "[REDACTED_SECRET]",
    "authorization": "[REDACTED_AUTHORIZATION]",
    "session_id": "[REDACTED_SESSION]",
    "private_key": "[REDACTED_PRIVATE_KEY]",
    "secret": "[REDACTED_SECRET]",
}
_TAG = re.compile(r"^[A-F0-9]{8}$")


class Pseudonymizer:
    """Keep identifier mappings in memory and scoped to one investigation."""

    def __init__(self, *, context_tag: str | None = None) -> None:
        tag = secrets.token_hex(4).upper() if context_tag is None else context_tag
        if not isinstance(tag, str) or not _TAG.fullmatch(tag):
            raise ValueError("context_tag must be exactly eight uppercase hex characters")
        self._tag = tag
        self._mapping: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = defaultdict(int)

    def pseudonymize(self, value: Any, kind: str) -> str:
        """Return a stable, context-local alias for a non-secret entity."""
        if kind in _REDACTIONS:
            return _REDACTIONS[kind]
        if kind not in _PREFIXES:
            raise ValueError(f"unsupported pseudonym kind: {kind}")
        text = str(value)
        if is_pseudonym(text, context_tag=self._tag):
            return text
        canonical = canonical_entity(kind, text)
        if kind in {"ipv4", "ipv6", "ip_address"}:
            try:
                canonical_value = str(ipaddress.ip_address(text.strip("[]")))
            except ValueError:
                canonical_value = canonical[1]
            canonical = (kind, canonical_value)
        map_kind = "ip_address" if kind in {"ipv4", "ipv6"} else kind
        key = (map_kind, canonical[1])
        alias = self._mapping.get(key)
        if alias is None:
            prefix = _PREFIXES[kind]
            self._counters[prefix] += 1
            alias = f"{prefix}_{self._tag}_{self._counters[prefix]:03d}"
            self._mapping[key] = alias
        return alias

    def sanitize_text(self, text: str) -> str:
        """Replace detected spans while preserving unrelated message content."""
        matches = detect_text(text)
        if not matches:
            return text
        result = text
        for match in reversed(matches):
            replacement = self._replacement(match)
            result = result[: match.start] + replacement + result[match.end :]
        return result

    def sanitize_value(self, value: Any, *, field_name: str | None = None) -> Any:
        """Sanitize a scalar according to its known structured field role."""
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            entity_kind = entity_kind_for_field(field_name)
            if entity_kind:
                return self.pseudonymize(value, entity_kind)
            return value
        if not isinstance(value, str):
            raise TypeError("sanitize_value accepts only JSON scalar values")
        matches = detect_text(value, field_name=field_name)
        if not matches:
            return value
        if len(matches) == 1 and matches[0].start == 0 and matches[0].end == len(value):
            return self._replacement(matches[0])
        result = value
        for match in reversed(matches):
            result = (
                result[: match.start]
                + self._replacement(match)
                + result[match.end :]
            )
        return result

    def _replacement(self, match: SensitiveMatch) -> str:
        if match.kind in _REDACTIONS:
            return _REDACTIONS[match.kind]
        return self.pseudonymize(match.value, match.kind)
