"""Parser for the LogHub-2k Linux syslog sample."""

from __future__ import annotations

import re
import ipaddress

from data_engineering.common import build_event, parse_syslog_timestamp_parts


_LINE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?:--\s+)?(?P<process>[\w./-]+(?:\([^)]*\))?)"
    r"(?:\[(?P<pid>\d+)\])?:?\s*"
    r"(?P<message>.*)$"
)
_ADDRESS_PREFIX = re.compile(
    r"^(?P<address>\d{1,3}(?:\.\d{1,3}){3}):\s*(?P<message>.*)$"
)


def parse_line(line: str, line_number: int) -> dict:
    match = _LINE.match(line.rstrip("\r\n"))
    if not match:
        return build_event(
            source="Linux",
            line_number=line_number,
            raw_line=line,
            parsed={
                "message": line,
                "matched": False,
                "parse_error": "line did not match Linux syslog prefix",
                "timestamp_precision": "unparsed",
            },
        )
    fields = match.groupdict()
    timestamp_parts = parse_syslog_timestamp_parts(
        fields["month"], fields["day"], fields["time"]
    )
    message = fields["message"]
    source_ip = None
    source_ip_context = None
    address_match = _ADDRESS_PREFIX.match(message)
    if address_match:
        candidate = address_match.group("address")
        try:
            source_ip = str(ipaddress.ip_address(candidate))
            source_ip_context = "unlabeled component prefix; direction is unknown"
            message = address_match.group("message")
        except ValueError:
            pass
    return build_event(
        source="Linux",
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
            "message": message,
            "source_ip": source_ip,
            "source_ip_context": source_ip_context,
            "matched": True,
        },
    )
