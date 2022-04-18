"""Unittests for Dnsx agent."""
import pathlib
import json
import tempfile


def testAgentDnsx_whenDomainNameAsset_RunScan(scan_message, test_agent, mocker, agent_mock):
    """Tests running the agent and emitting vulnerabilities."""
    with (pathlib.Path(__file__).parent / 'dnsx-test-output.json').open('r', encoding='utf-8') as o:
        mock_command_run = mocker.patch('subprocess.run', return_value=None)
        mocker.patch('json.load', return_value=json.load(o))
        mocker.patch('ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.set_add', return_value=True)
        test_agent.start()
        test_agent.process(scan_message)
        mock_command_run.assert_called_once()
        assert len(agent_mock) > 0
        assert agent_mock[0].selector == 'v3.asset.domain_name.dns_record'

def testAgentDnsx_whenDomainNameNotExist_EmptyResult(scan_message, test_agent, mocker, agent_mock):
    """Tests running the agent when dcommand does not generate results."""
    with tempfile.NamedTemporaryFile() as o:
        mock_command_run = mocker.patch('subprocess.run', return_value=None)
        mocker.patch('ostorlab.agent.mixins.agent_persist_mixin.AgentPersistMixin.set_add', return_value=True)
        emit_mock = mocker.patch('ostorlab.agent.agent.Agent.emit', return_value=None)
        test_agent.start()
        test_agent.process(scan_message)
        mock_command_run.assert_called_once()
        assert len(agent_mock) == 0
        emit_mock.assert_not_called()