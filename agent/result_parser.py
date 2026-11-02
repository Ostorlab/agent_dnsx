"""Module to parse dnsx json results."""

import collections.abc
import dataclasses
import typing

RECORDS = ["a", "aaaa", "cname", "ns", "txt", "ptr", "mx"]
SOA_RECORD = "soa"
# dnsx returns SOA entries as objects and omits zero values, so each field is paired
# with what an absent key stands for.
SOA_FIELDS = {
    "ns": ".",
    "mailbox": ".",
    "serial": "0",
    "refresh": "0",
    "retry": "0",
    "expire": "0",
    "minttl": "0",
}


@dataclasses.dataclass
class Record:
    """Record dataclass to pass to the emit method."""

    record: str
    value: list[str]


def _format_soa(entries: collections.abc.Sequence[typing.Any]) -> list[str]:
    """Render dnsx SOA entries as zone file presentation strings.

    Args:
        entries: SOA entries as returned by dnsx.

    Returns:
        One presentation string per entry.
    """
    values = []
    for entry in entries:
        if not isinstance(entry, dict):
            values.append(str(entry))
            continue
        fields = [
            str(entry.get(field, default)) for field, default in SOA_FIELDS.items()
        ]
        values.append(" ".join(fields))
    return values


def parse_results(
    results: collections.abc.Sequence[dict[str, typing.Any]],
) -> collections.abc.Iterator[Record]:
    """Parses JSON generated Dnsx results and yield record entries.

    Args:
        results: Parsed JSON output.

    Yields:
        Record entry.
    """
    for result in results:
        for key in RECORDS:
            value = result.get(key)
            if value is not None:
                yield Record(record=key, value=value)
        soa_entries = result.get(SOA_RECORD)
        if soa_entries is not None:
            yield Record(record=SOA_RECORD, value=_format_soa(soa_entries))
