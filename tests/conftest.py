"""Pytest fixture for the Dnsx agent."""
import json
import pathlib

import pytest
from ostorlab.agent import definitions as agent_definitions
from ostorlab.agent import message
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.utils import defintions as utils_definitions

from agent import dnsx_agent


@pytest.fixture
def scan_message():
    """Creates a dummy message of type v3.asset.domain_name to be used by the agent for testing purposes.
    """
    selector = 'v3.asset.domain_name'
    msg_data = {
        'name': 'ostorlab.co',
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def test_agent1():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/dnsx',
            bus_url='NA',
            bus_exchange_topic='NA',
            redis_url='redis://redis',
            args=[
                utils_definitions.Arg(**{
                    'name': 'wordlist',
                    'type': 'string',
                    'value': json.dumps('agent/wordlists/100_list.txt').encode()
                }),
            ],
            healthcheck_port=5301)
        return dnsx_agent.DnsxAgent(definition, settings)

@pytest.fixture
def test_agent2():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/dnsx',
            bus_url='NA',
            bus_exchange_topic='NA',
            redis_url='redis://redis',
            args=[],
            healthcheck_port=5302)
        return dnsx_agent.DnsxAgent(definition, settings)


@pytest.fixture
def test_agent3():
    with (pathlib.Path(__file__).parent.parent / 'ostorlab.yaml').open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key='agent/ostorlab/dnsx',
            bus_url='NA',
            bus_exchange_topic='NA',
            redis_url='redis://redis',
            args=[
                utils_definitions.Arg(**{
                    'name': 'wordlist',
                    'type': 'string',
                    'value': json.dumps('agent/wordlists/100_list.txt').encode()
                }),
                utils_definitions.Arg(name='max_subdomains', type='int', value=json.dumps(1).encode()),
            ],
            healthcheck_port=5303)
        return dnsx_agent.DnsxAgent(definition, settings)
