"""Dnsx Agent implementation"""

import logging
import subprocess
import tempfile
import json
import re
from typing import Any
from typing import List
from typing import Optional

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
IP_SELECTOR_PREFIX = "v3.asset.ip"
PTR_RECORD = "ptr"
_DNSX_RESOLVERS: str = ",".join(
    (
        "1.1.1.1",  # Cloudflare primary.
        "1.0.0.1",  # Cloudflare secondary.
        "8.8.8.8",  # Google Public DNS primary.
        "8.8.4.4",  # Google Public DNS secondary.
        "9.9.9.9",  # Quad9 primary.
        "149.112.112.112",  # Quad9 secondary.
    )
)


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
        if message.selector.startswith(IP_SELECTOR_PREFIX):
            self._process_ip(message)
        else:
            self._process_domain(message)

    def _process_domain(self, message: m.Message) -> None:
        """Run the DNS enrichment flow for a domain name asset."""
        domain = message.data["name"]
        wordlist = self.args.get("wordlist")
        logger.info("scanning domain %s", domain)
        if not self.set_add(b"agent_dnsx_asset", domain):
            logger.info("target %s/ was processed before, exiting", domain)
            return
        if self._is_domain_in_scope(domain) is False:
            return

        results = self._run_dnsx_resolve(domain)
        if results is not None:
            self._emit_results(domain, results)

        if wordlist is not None:
            results = self._run_dnsx(domain, wordlist)
            if results is not None:
                self._emit_results(domain, results)

    def _process_ip(self, message: m.Message) -> None:
        """Run a reverse PTR lookup for an IP asset and emit discovered hostnames."""
        ip = message.data["host"]
        logger.info("running reverse PTR lookup for IP %s", ip)
        if not self.set_add(b"agent_dnsx_ip_asset", ip):
            logger.info("target %s/ was processed before, exiting", ip)
            return

        results = self._run_dnsx_ptr(ip)
        if results is not None:
            self._emit_ptr_results(ip, results)

    def _is_domain_in_scope(self, domain: str) -> bool:
        """Check if a domain is in the scan scope with a regular expression."""
        if self._scope_domain_regex is None:
            return True
        domain_in_scope = re.match(self._scope_domain_regex, domain)
        if domain_in_scope is None:
            logger.warning(
                "Domain %s is not in scanning scope %s",
                domain,
                self._scope_domain_regex,
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
                json.loads(l)
                for l in result.stdout.decode().split("\n")  # noqa: E741
                if l != ""  # noqa: E741
            ]
        else:
            logger.warning("Empty result file for domain %s", domain)

    def _prepare_command(self, domain: str, wordlist: str | None) -> list[str]:
        """Prepare dnsx command."""
        command: list[str] = [
            "dnsx",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-ns",
            "-txt",
            "-ptr",
            "-mx",
            "-resp",
            "-json",
            "-r",
            _DNSX_RESOLVERS,
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
                    json.loads(l)
                    for l in result.stdout.decode().split("\n")  # noqa: E741
                    if l != ""  # noqa: E741
                ]
            else:
                logger.warning("Empty result file for domain %s", domain)

    def _prepare_command_resolve(self, domain_file: str) -> list[str]:
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
            "-resp",
            "-json",
            "-r",
            _DNSX_RESOLVERS,
            "-l",
            domain_file,
        ]

    def _emit_ptr_results(self, ip: str, results: list[dict[str, Any]]) -> None:
        """Emit PTR record evidence and discovered hostnames for an IP asset.

        For PTR records, the ``name`` field of the emitted
        ``v3.asset.domain_name.dns_record`` evidence carries the reversed IP
        address rather than a domain name, so the origin of the discovered
        hostnames remains visible to downstream agents.
        """
        for record in result_parser.parse_results(results):
            if record.record != PTR_RECORD or len(record.value) == 0:
                continue
            logger.info("emitting result for %s", record)
            self.emit(
                selector="v3.asset.domain_name.dns_record",
                data={
                    "name": ip,
                    "record": record.record,
                    "values": record.value,
                },
            )
            for hostname in record.value:
                hostname = hostname.rstrip(".")
                if not self.set_add(b"agent_dnsx_ptr_hostname", hostname):
                    logger.info("hostname %s was emitted before, skipping", hostname)
                    continue
                self.emit(selector="v3.asset.domain_name", data={"name": hostname})

    def _run_dnsx_ptr(self, ip: str) -> list[dict[str, Any]] | None:
        """Run dnsx reverse PTR lookup for an IP and returns the results."""
        with tempfile.NamedTemporaryFile() as input_ip:
            input_ip.write(ip.encode())
            input_ip.flush()
            command = self._prepare_command_ptr(input_ip.name)
            logger.info("running command %s", command)
            result = subprocess.run(command, capture_output=True, check=False)
            if result.returncode == 0 and result.stdout != b"":
                return [
                    json.loads(l)
                    for l in result.stdout.decode().split("\n")  # noqa: E741
                    if l != ""  # noqa: E741
                ]
            else:
                logger.warning("Empty result file for IP %s", ip)

    def _prepare_command_ptr(self, ip_file: str) -> list[str]:
        """Prepare dnsx reverse PTR lookup command."""
        return [
            "dnsx",
            "-silent",
            "-ptr",
            "-resp",
            "-json",
            "-r",
            _DNSX_RESOLVERS,
            "-l",
            ip_file,
        ]


if __name__ == "__main__":
    logger.info("starting agent ...")
    DnsxAgent.main()
