"""Dnsx Agent implementation"""
import logging
import subprocess
import tempfile
import pathlib
import json
from rich import logging as rich_logging
from typing import Dict, List

from ostorlab.agent import agent
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


class DnsxAgent(agent.Agent):
    """dnsx open source Agent implementation."""

    def process(self, message: m.Message) -> None:
        """Trigger dnsx scan and emits findings

        Args:
            message:
        """
        domain = message.data['name']
        logger.info('scanning domain %s', domain)
        results = self._run_dnsx(domain)
        self._emit_results(domain, results)

    def _emit_results(self, domain: str, results: Dict) -> None:
        """Parses results and emits records."""
        for record in result_parser.parse_results(results):
            self.emit(selector='v3.asset.domain_name',
                      data={'name': domain, 'record': record.record, 'value': record.value})
            if record.record == 'cname':
                for d in record.value:
                    self.emit(selector='v3.asset.domain_name', data={'name': d})

    def _run_dnsx(self, domain: str):
        """Run dnsx and returns the results."""
        with tempfile.NamedTemporaryFile(suffix=OUTPUT_SUFFIX) as f,\
                tempfile.NamedTemporaryFile(suffix=OUTPUT_SUFFIX) as t:
            f.write(domain.encode())
            command = self._prepare_command(pathlib.Path(f.name).name, pathlib.Path(t.name).name)
            logger.info('running command %s', command)
            subprocess.run(command, check=False)
            return json.load(t)

    def _prepare_command(self, input, output) -> List[str]:
        """Prepare dnsx command."""
        return ['dnsx', '-silent', '-a', '-aaaa', '-cname', '-ns',
                '-txt', '-ptr', '-mx', '-soa', '-resp', '-json', output, '-l', input]


if __name__ == '__main__':
    logger.info('starting agent ...')
    DnsxAgent.main()
