"""Unittests for Dnsx agent."""
from typing import List, Dict

import pytest_subprocess
from ostorlab.agent.message import message

from agent import dnsx_agent


def testAgentDnsx_whenDomainNameAssetWithWordlist_runScan(
    scan_message, test_agent1, agent_mock, agent_persist_mock, fp
):
    """Tests running the agent and emitting vulnerabilities."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-soa",
            "-resp",
            "-json",
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )
    fp.register(
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -d ostorlab.co "
        "-w agent/wordlists/100_list.txt",
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    test_agent1.start()
    test_agent1.process(scan_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"


def testAgentDnsx_whenDomainNameAsset_runScan(
    scan_message, test_agent2, agent_mock, agent_persist_mock, fp
):
    """Tests running the agent and emitting vulnerabilities."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-soa",
            "-resp",
            "-json",
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )
    fp.register(
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -d ostorlab.co "
        "-w agent/wordlists/100_list.txt",
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    test_agent2.start()
    test_agent2.process(scan_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"


def testAgentDnsx_whenMaxSubDomainsSet_runScan(
    scan_message, test_agent3, agent_mock, agent_persist_mock, fp
):
    """Tests running the agent and emitting vulnerabilities."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-soa",
            "-resp",
            "-json",
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )
    fp.register(
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -d ostorlab.co "
        "-w agent/wordlists/100_list.txt",
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    test_agent3.start()
    test_agent3.process(scan_message)

    assert len(agent_mock) == 4
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"


def testAgentDnsx_withDomainScopeArgAndDomainMessageInScope_runScan(
    scan_message: message.Message,
    dnsx_agent_with_domain_scope_arg: dnsx_agent.DnsxAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
    fp: pytest_subprocess.FakeProcess,
):
    """Ensure the domain scope argument is enforced, and domains in the scope should be scanned."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-soa",
            "-resp",
            "-json",
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )
    fp.register(
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -d ostorlab.co "
        "-w agent/wordlists/100_list.txt",
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_agent_with_domain_scope_arg.start()
    dnsx_agent_with_domain_scope_arg.process(scan_message)

    assert len(agent_mock) > 0
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"


def testAgentDnsx_withDomainScopeArgAndDomainMessageNotInScope_targetShouldNotBeScanned(
    dnsx_agent_with_domain_scope_arg: dnsx_agent.DnsxAgent,
    agent_mock: List[message.Message],
    agent_persist_mock: Dict[str | bytes, str | bytes],
    fp: pytest_subprocess.FakeProcess,
):
    """Ensure the domain scope argument is enforced, and domains not in the scope should not be scanned."""
    del agent_persist_mock
    scan_message = message.Message.from_data(
        "v3.asset.domain_name", data={"name": "www.google.com"}
    )
    fp.register(
        [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-soa",
            "-resp",
            "-json",
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )
    fp.register(
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -resp -json -d ostorlab.co "
        "-w agent/wordlists/100_list.txt",
        stdout='{"host":"www.ostorlab.co","resolver":["1.0.0.1:53","8.8.8.8:53","8.8.4.4:53","1.1.1.1:53"],'
        '"a":["164.90.232.184","3.67.255.218"],'
        '"aaaa":["2a05:d014:275:cb00:ec0d:12e2:df27:aa60","2a03:b0c0:3:d0::d23:4001"],'
        '"cname":["ostorlab-public-website.netlify.com"],"soa":["dns1.p04.nsone.net","hostmaster.nsone.net"],'
        '"has_internal_ips":false,"status_code":"NOERROR","timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_agent_with_domain_scope_arg.start()
    dnsx_agent_with_domain_scope_arg.process(scan_message)

    assert len(agent_mock) == 0
