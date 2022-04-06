"""Module to parse dnsx json results."""
import dataclasses
from typing import Dict, List

RECORDS = ['a', 'aaaa', 'cname', 'ns', 'txt', 'ptr', 'mx', 'soa']


@dataclasses.dataclass
class Record:
    """Record dataclass to pass to the emit method."""
    record: str
    value: List[str]


def parse_results(results: Dict):
    """Parses JSON generated Dnsx results and yield record entries.

    Args:
        results: Parsed JSON output.

    Yields:
        Record entry.
    """
    for key in RECORDS:
        value = results.get(key)
        if value is not None:
            yield Record(record=key, value=value)
