"""Module to parse dnsx json results."""

import dataclasses
from typing import List

RECORDS = ["a", "aaaa", "cname", "ns", "txt", "ptr", "mx"]


@dataclasses.dataclass
class Record:
    """Record dataclass to pass to the emit method."""

    record: str
    value: List[str]


def parse_results(results: List):
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
