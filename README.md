<h1 align="center">Agent dnsx</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_dnsx">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_dnsx agent is a fast and multi-purpose DNS toolkit._

<p align="center">
<img src="https://github.com/Ostorlab/agent_dnsx/blob/main/images/logo.png" alt="agent-dnsx" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for [dnsx](https://github.com/projectdiscovery/dnsx) DNS toolkitby by ProjectDiscovery.
  ## Getting Started
  The Dnsx Agent works collectively with other agents. It's job is to reverse a subdomain name and send all the identified records to the other agents reponsible for scanning those records.
  To perform your first scan, simply run the following command:
  ```shell
  ostorlab scan run --install --agent agent/ostorlab/dnsx --agent agent/ostorlab/subfinder domain-name your-domain.com
  ```
  This command will download and install agents  `agent/ostorlab/dnsx` & `agent/ostorlab/subfinder` and target the domain  `your-domain`.
  Subfinder Agent will scan for <your-domain>, and sends all identified subdomains, then Dnsx will reverse those subdomains and send the records.
  You can use any Agent expecting <v3.asset.domain_name> as an in-selector, like Nmap, OpenVas, etc.
  For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)
  ## Usage
  Agent Dnsx can be installed directly from the ostorlab agent store or built from this repository.
  ### Install directly from ostorlab agent store
  ```shell
  ostorlab agent install agent/ostorlab/dnsx
  ```
  ### Build directly from the repository
  1. To build the Dnsx agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine. If you have already installed ostorlab, you can skip this step.
  ```shell
  pip3 install ostorlab
  ```
  2. Clone this repository.
  ```shell
  git clone https://github.com/Ostorlab/agent_dnsx.git && cd agent_dnsx
  ```
  3. Build the agent image using ostorlab cli.
  ```shell
  ostortlab agent build --file=ostorlab.yaml
  ```
  You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.
  4. Run the agent using on of the following commands:
    * If you did not specify an organization when building the image:
      ```shell
      ostorlab scan run --agent agent//dnsx --agent agent//subfinder domain-name your-domain.com
      ```
    * If you specified an organization when building the image:
      ```shell
      ostorlab scan run --agent agent/[ORGANIZATION]/subfinder --agent agent/[ORGANIZATION]/dnsx  domain-name your-domain.com

  ## License
  [Apache](./LICENSE)license: Apache-2.0