# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately via [GitHub Security Advisories](../../security/advisories/new)
or by emailing the repository maintainer directly.

Include as much detail as possible:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or proof-of-concept.
- Affected files, scripts, or workflows.

We aim to acknowledge reports within 5 business days and to release a fix or
mitigation within 30 days, depending on severity.

## Trust Model

This repository uses a signed-manifest trust model to prevent unauthorised
software from being deployed via Azure Machine Configuration:

- `manifests/software.manifest.json` and `scripts/installers/package-allowlist.json`
  must each be signed with an ECDSA P-256 private key before CI will build or deploy.
- The corresponding public key is stored as the GitHub secret
  `MANIFEST_SIGNING_PUBLIC_KEY_PEM` and is verified by CI on every workflow run.
- **Never weaken or bypass signature verification.** Removing or short-circuiting
  `Verify-Manifest.ps1` calls is a security violation.
- Signing keys must be stored in Azure Key Vault; private keys must never be
  committed to source control.

See [`docs/KEY-MANAGEMENT.md`](docs/KEY-MANAGEMENT.md) for key generation,
rotation, and access-control guidance.

## Supported Versions

This project does not publish versioned releases. The `main` branch is the
supported version. Apply fixes by updating your fork or copy to the latest `main`.
