# Security policy

supermcp holds the credentials for the systems it connects to and
decides who may call them, so a flaw in it is a flaw in all of those
systems. This file says how to tell us about one and what happens next.

## Reporting a vulnerability

Report it privately through GitHub:

<https://github.com/supermcpco/supermcp/security/advisories/new>

Only the maintainers see a private report, and the conversation, the fix
and the eventual advisory all happen in the same place.

Do not open a public issue, pull request or discussion about it. There
is no security email address. If you cannot use GitHub, open a public
issue that asks for a private channel and says nothing about the
problem, and we will reply there with one.

## What to include

- The version: `supermcp version`, or the image tag and digest.
- How it is deployed: Docker Compose, the Helm chart, or the binary.
- What an attacker needs first: nothing, a network position, an account
  in a workspace (with which role), an API key, an MCP client.
- Steps to reproduce, as short as you can make them. A script or a
  request sequence beats a description.
- What you think the impact is.
- Whether anyone else knows, and how you would like to be credited.

Use throwaway credentials in anything you send. Do not send real
credentials, tokens or anyone's data, including your own.

## What happens next

- We acknowledge the report within 3 business days.
- We tell you whether we can reproduce it and how severe we think it is.
  If we disagree with you about either, we say why.
- For a high or critical issue, we ship a fix, or send you a plan with
  dates, within 30 days of the report. Lower severities go into a normal
  release, and we tell you which one.
- We keep you informed in the advisory thread until it is closed.
- For a confirmed issue we request a CVE through GitHub and credit you
  in the advisory, unless you would rather not be named.

## Supported versions

Fixes are released as a patch to the latest minor release of the current
major version. Older minor releases are not patched; `docs/UPGRADING.md`
says what moving to the latest one takes.

| Version | Supported |
|---|---|
| 1.2.x | Yes |
| Earlier than 1.2 | No |

## Disclosure

Disclosure is coordinated. We publish the advisory when a fixed release
is out, and ask you to wait until then.

The default deadline is 90 days from the report. If there is no fix by
then, we agree a date with you, and after 90 days you may publish either
way. If an issue is being exploited, we publish a mitigation as soon as
we have one, fix or not.

## Scope

In scope:

- The code in this repository: the server, the admin API, the MCP
  endpoint, the OAuth authorisation server, the web interface, the
  command line, and the adapters as they ship in the catalogue.
- The container image, `ghcr.io/supermcpco/supermcp`.
- The Helm chart, `charts/supermcp` and
  `oci://ghcr.io/supermcpco/charts/supermcp`.
- The release artifacts and their signatures, SBOMs and provenance.

Out of scope:

- The third-party APIs the adapters call. Report a flaw in one of them
  to its vendor. How supermcp handles what such an API sends back is in
  scope.
- Denial of service against a self-hosted instance you do not own. Test
  against an instance you run yourself; the Docker Compose quickstart in
  `README.md` starts one.
- Postgres, Redis, Kubernetes and the other things supermcp runs on,
  unless supermcp configures them unsafely.
- Scanner output with no demonstrated impact on supermcp.

## What we do on our side

- [docs/compliance/shared-responsibility.md](docs/compliance/shared-responsibility.md)
  says what the software does about tenant isolation, encryption,
  authentication, the audit trail and outbound requests, and what is
  left to the operator.
- [docs/compliance/incident-response.md](docs/compliance/incident-response.md)
  is for the operator of an instance. It says how to contain and record
  an incident, and when to report a flaw here.
- [docs/compliance/dr-runbook.md](docs/compliance/dr-runbook.md) says how
  to restore an instance from a Postgres backup.
- [docs/compliance/controls.md](docs/compliance/controls.md) maps common
  control expectations to the mechanism that meets each, with the
  partial ones marked as partial.
- Every pull request and every push to `main` runs `govulncheck`,
  `gosec` and `gitleaks` in CI.
- Releases are signed. cosign signs the checksums, the image and the
  chart keylessly from the release workflow; each archive ships an SBOM;
  SLSA provenance is attached to the release. The release notes carry
  the command that verifies the checksums.
