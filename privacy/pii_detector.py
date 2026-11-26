"""Field-aware detection of common personal and credential-like values."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SensitiveMatch:
    kind: str
    value: str
    path: str | None
    start: int
    end: int
    detector: str


_IPV4 = re.compile(
    r"(?<![A-Za-z0-9_.])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])"
)
_IPV6 = re.compile(
    r"(?<![A-Za-z0-9_.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"[0-9A-Fa-f]{0,4}(?![A-Za-z0-9_])"
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
_MAC = re.compile(
    r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{2}[:-]){5}"
    r"[A-Fa-f0-9]{2}(?![A-Fa-f0-9])"
)
_PHONE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[ .()-]?)?"
    r"(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}(?!\w)"
)
_HOST_FIELD = re.compile(
    r"\b(?:hostname|host|server)\s*[=:]\s*"
    r"(?P<value>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)",
    re.IGNORECASE,
)
_HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)
_USERNAME = re.compile(
    r"\b(?:username|user_name|user|account(?:_id)?)\s*[=:]\s*"
    r"(?P<value>['\"]?[A-Za-z0-9_.@\\-]+)",
    re.IGNORECASE,
)
_USER_CONTEXT = re.compile(
    r"(?<![A-Za-z0-9_-])(?:invalid\s+user|user)\s+"
    r"(?P<value>[A-Za-z0-9_.@\\-]+)",
    re.IGNORECASE,
)
_LOGIN_CONTEXT = re.compile(
    r"\bfor\s+(?P<value>[A-Za-z0-9_.@\\-]+)\s+from\b",
    re.IGNORECASE,
)
_SENSITIVE_PATH = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/][^\s,;\"']+"
    r"|/(?:home|Users|root)/[^\s,;\"']+"
    r"|/etc/(?:shadow|sudoers)(?:/[^\s,;\"']*)?"
    r"|/var/lib/[^\s,;\"']+)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE,
)
_AUTHORIZATION = re.compile(
    r"\b(?:proxy-)?authorization\s*[:=]\s*(?:bearer|basic|token)\s+\S+",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"\b(?P<key>password|passwd|passphrase|pwd|api[_-]?key|api[_-]?token|"
    r"session[_-]?token|access[_-]?token|refresh[_-]?token|"
    r"bearer[_-]?token|auth[_-]?token|"
    r"token|client[_-]?secret|secret|session(?:[_-]?id)?|"
    r"authorization|cookie|set-cookie)\b\s*[:=]\s*"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&,;#]+)",
    re.IGNORECASE,
)
_TOKEN_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
_REDACTION = re.compile(r"^\[REDACTED_[A-Z_]+\]$")
_PSEUDONYM = re.compile(
    r"^(?:IP|USER|HOST|EMAIL|PHONE|MAC|PATH)_"
    r"(?P<context>[A-F0-9]{8})_\d{3,}$"
)

_ENTITY_FIELDS = {
    "source_ip": "ip_address",
    "src_ip": "ip_address",
    "remote_ip": "ip_address",
    "client_ip": "ip_address",
    "ip_address": "ip_address",
    "ip": "ip_address",
    "username": "username",
    "user_name": "username",
    "user": "username",
    "account": "username",
    "account_id": "username",
    "account_identifier": "username",
    "user_identifier": "username",
    "user_id": "username",
    "uid": "username",
    "hostname": "hostname",
    "host_name": "hostname",
    "host": "hostname",
    "server_name": "hostname",
    "email": "email",
    "email_address": "email",
    "phone": "phone_number",
    "phone_number": "phone_number",
    "mobile": "phone_number",
    "mac": "mac_address",
    "mac_address": "mac_address",
    "file_path": "file_path",
    "filepath": "file_path",
    "path": "file_path",
    "cwd": "file_path",
}

_SECRET_FIELDS = {
    "password": "password",
    "passwd": "password",
    "passphrase": "password",
    "pwd": "password",
    "api_key": "api_key",
    "apikey": "api_key",
    "api_token": "access_token",
    "session_token": "access_token",
    "access_token": "access_token",
    "refresh_token": "access_token",
    "bearer_token": "access_token",
    "auth_token": "access_token",
    "token": "access_token",
    "client_secret": "secret",
    "secret": "secret",
    "credential": "secret",
    "credentials": "secret",
    "session_id": "session_id",
    "session_identifier": "session_id",
    "sessionid": "session_id",
    "authorization": "authorization",
    "authorization_header": "authorization",
    "auth_header": "authorization",
    "cookie": "session_id",
    "set_cookie": "session_id",
    "private_key": "private_key",
    "ssh_private_key": "private_key",
}

_SECRET_KEY = re.compile(
    r"(?:^|_)(?:password|passwd|passphrase|pwd|api_key|api_token|"
    r"session_token|access_token|refresh_token|bearer_token|auth_token|token|"
    r"client_secret|secret|session_id|sessionid|authorization|"
    r"credential|credentials|auth_header|cookie|set_cookie|"
    r"private_key|ssh_private_key)$",
    re.IGNORECASE,
)


def _normalized_field_name(field_name: str | None) -> str:
    if not field_name:
        return ""
    field_name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", field_name.strip())
    field_name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", field_name)
    return field_name.lower().replace("-", "_").replace(" ", "_")


def secret_kind_for_field(field_name: str | None) -> str | None:
    key = _normalized_field_name(field_name)
    if key in _SECRET_FIELDS:
        return _SECRET_FIELDS[key]
    if _SECRET_KEY.search(key):
        return "secret"
    return None


def entity_kind_for_field(field_name: str | None) -> str | None:
    return _ENTITY_FIELDS.get(_normalized_field_name(field_name))


def is_pseudonym(value: str, *, context_tag: str | None = None) -> bool:
    match = _PSEUDONYM.fullmatch(value)
    if match is None:
        return False
    return context_tag is None or match.group("context") == context_tag


def _secret_kind_from_key(key: str) -> str:
    normalized = key.lower().replace("-", "_")
    return secret_kind_for_field(normalized) or "secret"


def _match(
    kind: str,
    text: str,
    start: int,
    end: int,
    path: str | None,
    detector: str,
) -> SensitiveMatch:
    return SensitiveMatch(kind, text[start:end], path, start, end, detector)


def _canonical_ip(value: str) -> str:
    candidate = value.strip("[](){}<>,'\"")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return value


def _text_candidates(text: str, path: str | None) -> list[SensitiveMatch]:
    candidates: list[SensitiveMatch] = []

    for match in _PRIVATE_KEY.finditer(text):
        candidates.append(
            _match("private_key", text, match.start(), match.end(), path, "pattern")
        )
    for match in _AUTHORIZATION.finditer(text):
        candidates.append(
            _match(
                "authorization",
                text,
                match.start(),
                match.end(),
                path,
                "pattern",
            )
        )
    for match in _SECRET_ASSIGNMENT.finditer(text):
        start, end = match.span("value")
        if _REDACTION.fullmatch(text[start:end].strip("\"'")):
            continue
        candidates.append(
            _match(
                _secret_kind_from_key(match.group("key")),
                text,
                start,
                end,
                path,
                "pattern",
            )
        )
    for pattern in _TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            candidates.append(
                _match("access_token", text, match.start(), match.end(), path, "pattern")
            )

    for match in _IPV4.finditer(text):
        value = match.group(0)
        if (
            match.end() + 1 < len(text)
            and text[match.end()] == "."
            and text[match.end() + 1].isalnum()
        ):
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        candidates.append(
            SensitiveMatch("ipv4", str(address), path, match.start(), match.end(), "pattern")
        )
    for match in _IPV6.finditer(text):
        value = match.group(0)
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        candidates.append(
            SensitiveMatch("ipv6", str(address), path, match.start(), match.end(), "pattern")
        )
    for match in _EMAIL.finditer(text):
        candidates.append(
            _match("email", text, match.start(), match.end(), path, "pattern")
        )
    for match in _MAC.finditer(text):
        candidates.append(
            _match("mac_address", text, match.start(), match.end(), path, "pattern")
        )
    for match in _PHONE.finditer(text):
        candidates.append(
            _match("phone_number", text, match.start(), match.end(), path, "pattern")
        )
    for match in _SENSITIVE_PATH.finditer(text):
        candidates.append(
            _match("file_path", text, match.start(), match.end(), path, "pattern")
        )
    for match in _HOST_FIELD.finditer(text):
        start, end = match.span("value")
        candidates.append(_match("hostname", text, start, end, path, "pattern"))
    for match in _HOSTNAME.finditer(text):
        candidates.append(
            _match("hostname", text, match.start(), match.end(), path, "pattern")
        )
    for pattern in (_USERNAME, _USER_CONTEXT, _LOGIN_CONTEXT):
        for match in pattern.finditer(text):
            start, end = match.span("value")
            value = text[start:end].strip("\"'")
            offset = len(text[start:end]) - len(text[start:end].lstrip("\"'"))
            candidates.append(
                SensitiveMatch(
                    "username",
                    value,
                    path,
                    start + offset,
                    end,
                    "pattern",
                )
            )

    priority = {
        "private_key": 100,
        "authorization": 95,
        "password": 94,
        "api_key": 94,
        "access_token": 94,
        "session_id": 94,
        "secret": 94,
        "email": 70,
        "ipv4": 65,
        "ipv6": 65,
        "mac_address": 60,
        "phone_number": 55,
        "file_path": 50,
        "hostname": 45,
        "username": 40,
    }
    selected: list[SensitiveMatch] = []
    for candidate in sorted(
        candidates,
        key=lambda item: (
            -priority.get(item.kind, 0),
            item.start,
            -(item.end - item.start),
        ),
    ):
        if any(
            candidate.start < existing.end and existing.start < candidate.end
            for existing in selected
        ):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end, item.kind))


def detect_text(
    text: str,
    *,
    field_name: str | None = None,
    path: str | None = None,
    allow_pseudonym: bool = False,
) -> list[SensitiveMatch]:
    """Find sensitive spans in text, using a structured field's role when known."""
    if not isinstance(text, str) or not text:
        return []
    if _REDACTION.fullmatch(text) or (
        allow_pseudonym and is_pseudonym(text)
    ):
        return []

    secret_kind = secret_kind_for_field(field_name)
    if secret_kind:
        return [SensitiveMatch(secret_kind, text, path, 0, len(text), "field")]

    entity_kind = entity_kind_for_field(field_name)
    if entity_kind:
        return [SensitiveMatch(entity_kind, text, path, 0, len(text), "field")]

    matches = _text_candidates(text, path)
    if allow_pseudonym:
        matches = [match for match in matches if not is_pseudonym(match.value)]
    return matches


def scan_sensitive(
    value: Any, *, path: str = "$", allow_pseudonyms: bool = False
) -> list[SensitiveMatch]:
    """Scan nested JSON-compatible values without printing or modifying them."""
    if isinstance(value, dict):
        return [
            match
            for key, child in value.items()
            for match in _scan_child(
                child, str(key), f"{path}.{key}", allow_pseudonyms
            )
        ]
    if isinstance(value, list):
        matches: list[SensitiveMatch] = []
        for index, child in enumerate(value):
            matches.extend(
                _scan_child(child, None, f"{path}[{index}]", allow_pseudonyms)
            )
        return matches
    if isinstance(value, str):
        return detect_text(value, path=path, allow_pseudonym=allow_pseudonyms)
    return []


def _scan_child(
    value: Any,
    field_name: str | None,
    path: str,
    allow_pseudonyms: bool,
) -> list[SensitiveMatch]:
    if isinstance(value, dict):
        if secret_kind_for_field(field_name):
            found: list[SensitiveMatch] = []
            for key, child in value.items():
                found.extend(
                    _scan_child(
                        child, field_name or key, f"{path}.{key}", allow_pseudonyms
                    )
                )
            return found
        return scan_sensitive(value, path=path, allow_pseudonyms=allow_pseudonyms)
    if isinstance(value, list):
        matches: list[SensitiveMatch] = []
        for index, child in enumerate(value):
            matches.extend(
                _scan_child(child, field_name, f"{path}[{index}]", allow_pseudonyms)
            )
        return matches
    if isinstance(value, str):
        return detect_text(
            value,
            field_name=field_name,
            path=path,
            allow_pseudonym=allow_pseudonyms,
        )
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
    ):
        text = str(value)
        kind = secret_kind_for_field(field_name) or entity_kind_for_field(field_name)
        if kind:
            return [SensitiveMatch(kind, text, path, 0, len(text), "field")]
    return []


def canonical_entity(kind: str, value: str) -> tuple[str, str]:
    """Return a comparison key without changing the displayed source value."""
    if kind in {"ipv4", "ipv6", "ip_address"}:
        return kind, _canonical_ip(value)
    if kind in {"email", "hostname", "mac_address", "username"}:
        return kind, value.casefold()
    if kind == "phone_number":
        return kind, re.sub(r"\D", "", value)
    if kind == "file_path":
        return kind, value.replace("\\", "/").casefold()
    return kind, value
