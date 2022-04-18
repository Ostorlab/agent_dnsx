"""Dnsx Agent implementation"""
import logging
import subprocess
import tempfile
import pathlib
import json
from rich import logging as rich_logging
from typing import Dict, List

from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent import message as m

from agent import result_parser


logging.basicConfig(
    format='%(message)s',
    datefmt='[%X]',
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level='INFO',
    force=True
)
logger = logging.getLogger(__name__)

OUTPUT_SUFFIX = '.json'


class DnsxAgent(agent.Agent, persist_mixin.AgentPersistMixin):
    """dnsx open source Agent implementation."""

    def __init__(self, agent_definition: agent_definitions.AgentDefinition,
                 agent_settings: runtime_definitions.AgentSettings) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)

    def process(self, message: m.Message) -> None:
        """Trigger dnsx scan and emits findings

        Args:
            message:
        """
        domain = message.data['name']
        logger.info('scanning domain %s', domain)
        if not self.set_add('agent_dnsx_asset', domain):
            logger.info('target %s/ was processed before, exiting', domain)
            return

        results = self._run_dnsx(domain)
        self._emit_results(domain, results)

    def _emit_results(self, domain: str, results: Dict) -> None:
        """Parses results and emits records."""
        for record in result_parser.parse_results(results):
            logger.info('emitting result for %s', record)
            self.emit(selector='v3.asset.domain_name.dns_record',
                      data={'name': domain, 'record': record.record, 'values': record.value})

    def _run_dnsx(self, domain: str):
        """Run dnsx and returns the results."""
        with tempfile.NamedTemporaryFile() as input_domain,\
                tempfile.NamedTemporaryFile() as output_domain:
            input_domain.write(domain.encode())
            input_domain.flush()
            command = self._prepare_command(str(pathlib.Path(input_domain.name)), str(pathlib.Path(output_domain.name)))
            logger.info('running command %s', command)
            subprocess.run(command, check=False)
            try:
                return json.load(output_domain)
            except json.JSONDecodeError:
                logger.info('Empty result file for domain %s', domain)

    def _prepare_command(self, domain_file, output) -> List[str]:
        """Prepare dnsx command."""
        return ['dnsx', '-silent', '-a', '-aaaa', '-cname', '-ns',
                '-txt', '-ptr', '-mx', '-soa', '-resp', '-json', '-o', output, '-l', domain_file]


if __name__ == '__main__':
    logger.info('starting agent ...')
    DnsxAgent.main()
