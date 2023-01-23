"""Dnsx Agent implementation"""
import logging
import subprocess
import tempfile
import json
import re
from typing import List, Optional

from rich import logging as rich_logging
from ostorlab.agent import agent, definitions as agent_definitions
from ostorlab.agent.mixins import agent_persist_mixin as persist_mixin
from ostorlab.runtimes import definitions as runtime_definitions
from ostorlab.agent.message import message as m

from agent import result_parser


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
    level="INFO",
    force=True,
)
logger = logging.getLogger(__name__)

OUTPUT_SUFFIX = ".json"


class DnsxAgent(agent.Agent, persist_mixin.AgentPersistMixin):
    """dnsx open source Agent implementation."""

    def __init__(
        self,
        agent_definition: agent_definitions.AgentDefinition,
        agent_settings: runtime_definitions.AgentSettings,
    ) -> None:
        agent.Agent.__init__(self, agent_definition, agent_settings)
        persist_mixin.AgentPersistMixin.__init__(self, agent_settings)
        self._scope_domain_regex: Optional[str] = self.args.get("scope_domain_regex")

    def process(self, message: m.Message) -> None:
        """Trigger dnsx scan and emits findings

        Args:
            message:
        """
        domain = message.data["name"]
        wordlist = self.args.get("wordlist")
        logger.info("scanning domain %s", domain)
        if not self.set_add(b"agent_dnsx_asset", domain):
            logger.info("target %s/ was processed before, exiting", domain)
            return
        if self._is_domain_in_scope(self._scope_domain_regex, domain) is False:
            return

        results = self._run_dnsx_resolve(domain)
        if results is not None:
            self._emit_results(domain, results)

        if wordlist is not None:
            results = self._run_dnsx(domain, wordlist)
            if results is not None:
                self._emit_results(domain, results)

    def _is_domain_in_scope(
        self, scope_domain_regex: Optional[str], domain: str
    ) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if scope_domain_regex is None:
            return True
        domain_in_scope = re.match(scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                scope_domain_regex,
            )
            return False
        else:
            return True

    def _emit_results(self, domain: str, results: List) -> None:
        """Parses results and emits records."""

        counter = 0
        for record in result_parser.parse_results(results):
            if self.args.get("max_subdomains") is not None and counter > self.args.get(
                "max_subdomains"
            ):
                break
            else:
                logger.info("emitting result for %s", record)
                self.emit(
                    selector="v3.asset.domain_name.dns_record",
                    data={
                        "name": domain,
                        "record": record.record,
                        "values": record.value,
                    },
                )
                counter += 1

    def _run_dnsx(self, domain: str, wordlist: Optional[str] = None):
        """Run dnsx and returns the results."""
        command = self._prepare_command(domain, wordlist)
        logger.info("running command %s", command)
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode == 0 and result.stdout != b"":
            return [
                json.loads(l) for l in result.stdout.decode().split("\n") if l != ""
            ]
        else:
            logger.warning("Empty result file for domain %s", domain)

    def _prepare_command(self, domain, wordlist: Optional[str]) -> List[str]:
        """Prepare dnsx command."""
        command = [
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
            "-d",
            domain,
        ]

        if wordlist is not None:
            command.extend(["-w", wordlist])
        return command

    def _run_dnsx_resolve(self, domain: str):
        """Run dnsx and returns the results."""
        with tempfile.NamedTemporaryFile() as input_domain:
            input_domain.write(domain.encode())
            input_domain.flush()
            command = self._prepare_command_resolve(input_domain.name)
            logger.info("running command %s", command)
            result = subprocess.run(command, capture_output=True, check=False)
            if result.returncode == 0 and result.stdout != b"":
                return [
                    json.loads(l) for l in result.stdout.decode().split("\n") if l != ""
                ]
            else:
                logger.warning("Empty result file for domain %s", domain)

    def _prepare_command_resolve(self, domain_file) -> List[str]:
        """Prepare dnsx command."""
        return [
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
            domain_file,
        ]


if __name__ == "__main__":
    logger.info("starting agent ...")
    DnsxAgent.main()
