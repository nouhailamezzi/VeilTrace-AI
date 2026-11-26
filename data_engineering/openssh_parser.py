"""Parser for the LogHub-2k OpenSSH syslog sample."""

from __future__ import annotations

import re

from data_engineering.common import build_event, parse_syslog_timestamp_parts


_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)


def parse_line(line: str, line_number: int) -> dict:
    match = _LINE.match(line.rstrip("\r\n"))
    if not match:
        return build_event(
            source="OpenSSH",
            line_number=line_number,
            raw_line=line,
            parsed={
                "message": line,
                "matched": False,
                "parse_error": "line did not match OpenSSH syslog prefix",
                "timestamp_precision": "unparsed",
            },
        )
    fields = match.groupdict()
    timestamp_parts = parse_syslog_timestamp_parts(
        fields["month"], fields["day"], fields["time"]
    )
    return build_event(
        source="OpenSSH",
        line_number=line_number,
        raw_line=line,
        parsed={
            "timestamp_raw": f"{fields['month']} {fields['day']} {fields['time']}",
            "timestamp": None,
            "timestamp_precision": "month-day-time",
            **timestamp_parts,
            "limitations": [
                "source timestamp omits year and timezone; normalized timestamp is null"
            ],
            "hostname": fields["hostname"],
            "process": fields["process"],
            "pid": fields["pid"],
            "message": fields["message"],
            "matched": True,
        },
    )
