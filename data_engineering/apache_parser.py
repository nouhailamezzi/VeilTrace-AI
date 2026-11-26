"""Parser for the LogHub-2k Apache error-log sample."""

from __future__ import annotations

import re

from data_engineering.common import build_event, parse_apache_timestamp


_LINE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s*(?P<message>.*)$"
)


def parse_line(line: str, line_number: int) -> dict:
    match = _LINE.match(line.rstrip("\r\n"))
    if not match:
        return build_event(
            source="Apache",
            line_number=line_number,
            raw_line=line,
            parsed={
                "message": line,
                "matched": False,
                "parse_error": "line did not match Apache error-log prefix",
                "timestamp_precision": "unparsed",
            },
        )
    fields = match.groupdict()
    timestamp, limitations, timestamp_parts = parse_apache_timestamp(fields["timestamp"])
    return build_event(
        source="Apache",
        line_number=line_number,
        raw_line=line,
        parsed={
            "timestamp_raw": fields["timestamp"],
            "timestamp": timestamp,
            "timestamp_precision": "second",
            **timestamp_parts,
            "limitations": limitations,
            "severity": fields["severity"],
            "message": fields["message"],
            "matched": True,
        },
    )
