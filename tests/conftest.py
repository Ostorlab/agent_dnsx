"""Pytest fixture for the Dnsx agent."""

import itertools
import json
import pathlib

import pytest
import pytest_subprocess
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent.message import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import definitions as utils_definitions

from agent import dnsx_agent

_RECORD_AGENT_PORTS = itertools.count(5310)


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes."""
    selector = "v3.asset.domain_name"
    msg_data = {
        "name": "ostorlab.co",
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def ip_v4_message():
    """Creates a dummy message of type v3.asset.ip.v4 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v4"
    msg_data = {
        "host": "8.8.8.8",
        "version": 4,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def ip_v6_message():
    """Creates a dummy message of type v3.asset.ip.v6 to be used by the agent for testing purposes."""
    selector = "v3.asset.ip.v6"
    msg_data = {
        "host": "2001:4860:4860::8888",
        "version": 6,
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent1():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="wordlist",
                    type="string",
                    value=json.dumps("agent/wordlists/100_list.txt").encode(),
                ),
            ],
            healthcheck_port=5301,
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def test_agent2():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=5302,
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def test_agent3():
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="wordlist",
                    type="string",
                    value=json.dumps("agent/wordlists/100_list.txt").encode(),
                ),
                utils_definitions.Arg(
                    name="max_subdomains", type="int", value=json.dumps(1).encode()
                ),
            ],
            healthcheck_port=5303,
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def dnsx_ip_agent(agent_mock: list[message.Message]):
    """DNSX Agent fixture without arguments for testing IP reverse PTR lookups."""
    del agent_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=5304,
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def dnsx_agent_with_domain_scope_arg(agent_mock: list[message.Message]):
    """DNSX Agent fixture with domain scope argument for testing purposes."""
    del agent_mock
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="scope_domain_regex",
                    type="string",
                    value=json.dumps(".*ostorlab.co").encode(),
                ),
            ],
            healthcheck_port=5301,
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def dnsx_record_agent() -> dnsx_agent.DnsxAgent:
    """DNSX Agent fixture without arguments, on a healthcheck port unique to each build."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[],
            healthcheck_port=next(_RECORD_AGENT_PORTS),
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def dnsx_record_wordlist_agent() -> dnsx_agent.DnsxAgent:
    """DNSX Agent fixture with a wordlist, on a healthcheck port unique to each build."""
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/dnsx",
            bus_url="NA",
            bus_exchange_topic="NA",
            redis_url="redis://redis",
            args=[
                utils_definitions.Arg(
                    name="wordlist",
                    type="string",
                    value=json.dumps("agent/wordlists/100_list.txt").encode(),
                ),
            ],
            healthcheck_port=next(_RECORD_AGENT_PORTS),
        )
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def register_tls_rpt_lookup(fp: pytest_subprocess.FakeProcess):
    """Register the TLS-RPT lookup the agent runs for every in scope domain."""

    def _register(stdout: str = "") -> None:
        fp.register(
            [
                "dnsx",
                "-silent",
                "-txt",
                "-resp",
                "-json",
                "-r",
                dnsx_agent._DNSX_RESOLVERS,
                "-l",
                fp.any(max=1),
            ],
            stdout=stdout,
        )

    return _register
