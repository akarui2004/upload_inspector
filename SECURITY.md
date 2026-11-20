# Security policy

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on
<https://github.com/akarui2004/upload_inspector/security/advisories/new>. Do not open a public
issue for a bypass.

Useful in a report: the file (or a script that builds it), the `check` options used, the result
you got, and what a real reader (browser, Office, PDF viewer, server) does with the file.

A file that is accepted but should not be (a bypass), a hostile file that crashes, hangs or
exhausts memory outside the sandbox, or `check` raising on hostile input are all vulnerabilities.
See [THREAT_MODEL.md](THREAT_MODEL.md) for what is out of scope.

## Response

- Acknowledgement within 3 business days.
- Assessment and a fix plan within 10 business days.
- Fixed releases are published to RubyGems with a GitHub security advisory (and a CVE when the
  issue warrants one). Reporters are credited unless they ask not to be.

## Supported versions

Only the latest minor release gets security fixes. The gem is pre-1.0: upgrade to the latest
0.x release to receive them.

| Version | Supported |
|---|---|
| latest 0.x | yes |
| older | no |
