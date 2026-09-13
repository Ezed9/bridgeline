# Security Policy

bridgeline's claim is that page content cannot become an instruction. A
vulnerability is anything that makes that false — above all, **any way for
content read during a crawl to cause an effect the committed plan did not
authorize**. Concretely:

- a request to a host, scheme, port or path outside the plan's `CrawlScope`;
- a file written outside the workspace;
- a value derived from page content reaching a destination argument (`fetch.url`,
  `write_file.path`) under the default policy;
- a plan that parses with a slot in a destination position;
- an SSRF to loopback, private, link-local or cloud-metadata addresses without
  `--allow-loopback`;
- a live URL surviving into rendered output (`report.summary`, `write_file.content`).

`bridgeline verify` is the regression harness for all of these. The ideal report
is a new attack in the shape of `src/bridgeline/verify/attacks.py` that makes it
exit non-zero.

## Reporting a vulnerability

Please report privately rather than in a public issue, through GitHub's
**[Report a vulnerability](https://github.com/Ezed9/bridgeline/security/advisories/new)**
(Security → Advisories).

Include, if you can: the instruction, the page content that triggers it, the
plan that was committed (`--dry-run` prints it), and the effect you observed.
Please make sure what you report is something you have reproduced.

## Out of scope — documented limitations, not vulnerabilities

These are stated in [SPEC.md](SPEC.md) §3, §5, §8 and [FINDINGS.md](FINDINGS.md):

- **Routing integrity.** A malicious *in-scope* page decides which in-scope pages
  are visited, in what order, and can exhaust the page budget. bridgeline claims
  confidentiality of destinations, not integrity of routing.
- **Extracted URLs are never fetched** under the default policy, even legitimate
  ones. `allow_tainted_sink` is an explicit, documented price.
- **DNS rebinding** between address validation and connection. Every resolved
  address is checked, but the connection is not pinned to it.
- **Taint is storage-granular.** A value laundered out of its `Tainted` wrapper
  by a future refactor loses Layer 1's witness; Layer 2 exists for that.
- **Extraction quality.** A wrong answer is not a leak.
- **A malicious trusted instruction**, model weight poisoning, OS or hardware
  side channels, and human social engineering.
- **Configurations with an API key set.** The security claim is measured only
  under `--models none`. Reports against a live model are welcome, but please
  confirm the effect also reproduces with the deterministic planner, or say
  plainly that it does not — that distinction is the finding.

Unsure? Report it privately anyway.

## Expectations

bridgeline is an early-stage project maintained on a best-effort basis. Reports
are acknowledged as quickly as possible, and reporters are credited if they want
to be.
