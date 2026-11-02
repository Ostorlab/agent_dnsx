"""Unittests for the dnsx result parser."""

from agent import result_parser


def testParseResults_whenRecordIsSoaObject_yieldsPresentationString():
    """dnsx returns SOA as an object, which cannot reach a repeated string proto field."""
    results = [
        {
            "host": "ostorlab.co",
            "soa": [
                {
                    "name": "ostorlab.co",
                    "ns": "dns1.p04.nsone.net.",
                    "mailbox": "hostmaster.nsone.net.",
                    "serial": 1,
                    "refresh": 43200,
                    "retry": 7200,
                    "expire": 1209600,
                    "minttl": 3600,
                }
            ],
        }
    ]

    records = {
        record.record: record.value for record in result_parser.parse_results(results)
    }

    assert records["soa"] == [
        "dns1.p04.nsone.net. hostmaster.nsone.net. 1 43200 7200 1209600 3600"
    ]


def testParseResults_whenSoaObjectIsPartial_skipsMissingFields():
    """A resolver may answer with only part of the SOA, which must not render as blanks."""
    results = [{"soa": [{"ns": "dns1.p04.nsone.net.", "serial": 7}]}]

    records = {
        record.record: record.value for record in result_parser.parse_results(results)
    }

    assert records["soa"] == ["dns1.p04.nsone.net. 7"]


def testParseResults_whenSoaIsListOfStrings_yieldsValuesUnchanged():
    """Older dnsx builds answered with plain strings, which stay usable as they are."""
    results = [{"soa": ["dns1.p04.nsone.net.", "hostmaster.nsone.net."]}]

    records = {
        record.record: record.value for record in result_parser.parse_results(results)
    }

    assert records["soa"] == ["dns1.p04.nsone.net.", "hostmaster.nsone.net."]
