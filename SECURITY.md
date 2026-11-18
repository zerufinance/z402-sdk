# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's private vulnerability reporting:

1. Go to https://github.com/zerufinance/z402-sdk/security/advisories/new
   (or the repository's **Security** tab, then **Report a vulnerability**).
2. Describe the issue, the affected package (`zeru-z402` on PyPI or npm) and version,
   and the steps to reproduce it.

Please do not open a public issue or pull request for a security problem.

We will acknowledge your report, keep you updated while we work on a fix, and credit
you in the advisory if you wish.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Scope

In scope: the `zeru-z402` Python and TypeScript packages in this repository, for example
a way to make a guarded payment go through when it should have been stopped, or a way to
make the SDK send the API key somewhere other than the configured HTTPS check API.
