"""Unittests for Dnsx agent."""

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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
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
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -caa -resp -json "
        f"-r {dnsx_agent._DNSX_RESOLVERS} -d ostorlab.co "
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
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
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -caa -resp -json "
        f"-r {dnsx_agent._DNSX_RESOLVERS} -d ostorlab.co "
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
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
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -caa -resp -json "
        f"-r {dnsx_agent._DNSX_RESOLVERS} -d ostorlab.co "
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
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
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -caa -resp -json "
        f"-r {dnsx_agent._DNSX_RESOLVERS} -d ostorlab.co "
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
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
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
        "dnsx -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -caa -resp -json "
        f"-r {dnsx_agent._DNSX_RESOLVERS} -d ostorlab.co "
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


def testAgentDnsx_whenIPv4AssetWithPtrRecord_emitsDomainNameAndDnsRecord(
    ip_v4_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests reverse PTR lookup for an IPv4 asset emits the discovered hostname and its DNS record evidence."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"8.8.8.8","resolver":["1.0.0.1:53","8.8.8.8:53"],'
        '"ptr":["dns.google"],"status_code":"NOERROR",'
        '"timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"
    assert agent_mock[0].data["name"] == "8.8.8.8"
    assert agent_mock[0].data["record"] == "ptr"
    assert agent_mock[0].data["values"] == ["dns.google"]
    assert agent_mock[1].selector == "v3.asset.domain_name"
    assert agent_mock[1].data["name"] == "dns.google"


def testAgentDnsx_whenIPv6AssetWithPtrRecord_emitsDomainNameAndDnsRecord(
    ip_v6_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests reverse PTR lookup for an IPv6 asset emits the discovered hostname and its DNS record evidence."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"2001:4860:4860::8888","resolver":["1.0.0.1:53","8.8.8.8:53"],'
        '"ptr":["dns.google"],"status_code":"NOERROR",'
        '"timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v6_message)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.asset.domain_name.dns_record"
    assert agent_mock[0].data["name"] == "2001:4860:4860::8888"
    assert agent_mock[0].data["record"] == "ptr"
    assert agent_mock[0].data["values"] == ["dns.google"]
    assert agent_mock[1].selector == "v3.asset.domain_name"
    assert agent_mock[1].data["name"] == "dns.google"


def testAgentDnsx_whenIPAssetWithoutPtrRecord_emitsNothing(
    ip_v4_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests an IP with no PTR record is handled gracefully and emits nothing."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout="",
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)

    assert len(agent_mock) == 0


def testAgentDnsx_whenIPLookupFails_emitsNothing(
    ip_v4_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests a failing PTR lookup does not crash the agent and emits nothing."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        returncode=1,
        stdout="",
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)

    assert len(agent_mock) == 0


def testAgentDnsx_whenSameIPProcessedTwice_processesItOnlyOnce(
    ip_v4_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests the same IP asset is not processed twice."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"8.8.8.8","resolver":["1.0.0.1:53","8.8.8.8:53"],'
        '"ptr":["dns.google"],"status_code":"NOERROR",'
        '"timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)
    dnsx_ip_agent.process(ip_v4_message)

    assert len(agent_mock) == 2


def testAgentDnsx_whenHostnameDiscoveredFromMultipleIPs_emitsHostnameOnce(
    ip_v4_message, ip_v6_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests the same hostname discovered from different IPs is emitted as a domain name only once."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"8.8.8.8","resolver":["1.0.0.1:53","8.8.8.8:53"],'
        '"ptr":["dns.google"],"status_code":"NOERROR",'
        '"timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
        occurrences=2,
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)
    dnsx_ip_agent.process(ip_v6_message)

    assert len(agent_mock) == 3
    domain_name_messages = [
        m for m in agent_mock if m.selector == "v3.asset.domain_name"
    ]
    assert len(domain_name_messages) == 1
    assert domain_name_messages[0].data["name"] == "dns.google"


def testAgentDnsx_whenPtrHostnameEndsWithDot_emitsNormalizedHostname(
    ip_v4_message, dnsx_ip_agent, agent_mock, agent_persist_mock, fp
):
    """Tests the trailing dot of a PTR hostname is stripped before emitting the domain name."""
    fp.register(
        [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"8.8.8.8","resolver":["1.0.0.1:53","8.8.8.8:53"],'
        '"ptr":["dns.google."],"status_code":"NOERROR",'
        '"timestamp":"2022-04-05T17:25:59.876762366+02:00"}',
    )

    dnsx_ip_agent.start()
    dnsx_ip_agent.process(ip_v4_message)

    domain_name_messages = [
        m for m in agent_mock if m.selector == "v3.asset.domain_name"
    ]
    assert len(domain_name_messages) == 1
    assert domain_name_messages[0].data["name"] == "dns.google"


def testAgentDnsx_whenDomainHasSoaRecord_emitsSoaAsPresentationString(
    scan_message: message.Message,
    test_agent2: dnsx_agent.DnsxAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    fp: pytest_subprocess.FakeProcess,
):
    """dnsx returns SOA as an object while every other record is a list of strings, so it
    must be rendered before it reaches a repeated string proto field."""
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"ostorlab.co","soa":[{"name":"ostorlab.co","ns":"dns1.p04.nsone.net.",'
        '"mailbox":"hostmaster.nsone.net.","serial":1,"refresh":43200,"retry":7200,'
        '"expire":1209600,"minttl":3600}],"status_code":"NOERROR"}',
    )

    test_agent2.start()
    test_agent2.process(scan_message)

    soa_messages = [m for m in agent_mock if m.data.get("record") == "soa"]
    assert len(soa_messages) == 1
    assert soa_messages[0].selector == "v3.asset.domain_name.dns_record"
    assert soa_messages[0].data["values"] == [
        "dns1.p04.nsone.net. hostmaster.nsone.net. 1 43200 7200 1209600 3600"
    ]


def testAgentDnsx_whenDomainHasCaaRecord_emitsCaaRecord(
    scan_message: message.Message,
    dnsx_record_agent: dnsx_agent.DnsxAgent,
    agent_mock: list[message.Message],
    agent_persist_mock: dict[str | bytes, str | bytes],
    fp: pytest_subprocess.FakeProcess,
):
    """CAA names the authorities allowed to issue certificates for the domain.

    dnsx returns the record values only, without the flags and tag a zone file carries,
    so an issue entry and an iodef entry are indistinguishable downstream.
    """
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
            "-caa",
            "-resp",
            "-json",
            "-r",
            dnsx_agent._DNSX_RESOLVERS,
            "-l",
            fp.any(max=1),
        ],
        stdout='{"host":"github.com","caa":["sectigo.com","globalsign.com",'
        '"letsencrypt.org","digicert.com"],"status_code":"NOERROR"}',
    )

    dnsx_record_agent.start()
    dnsx_record_agent.process(scan_message)

    caa_messages = [m for m in agent_mock if m.data.get("record") == "caa"]
    assert len(caa_messages) == 1
    assert caa_messages[0].selector == "v3.asset.domain_name.dns_record"
    assert caa_messages[0].data["values"] == [
        "sectigo.com",
        "globalsign.com",
        "letsencrypt.org",
        "digicert.com",
    ]
