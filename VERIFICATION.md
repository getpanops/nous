# Verifying nous bundles

All bundles published by this repository are signed with cosign keyless signing
(Sigstore/Fulcio) from GitHub Actions. Verification is required before applying.

## OCI artifact (online install)

```bash
cosign verify \
  --certificate-identity-regexp \
    "https://github.com/getpanops/nous/.github/workflows/build-bundle.yaml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/getpanops/nous:latest
```

The intel-updater CronJob runs this automatically before applying the bundle.

## Tarball (airgap install)

Download the `.zip` and `bundle.json` from the GitHub Release, then:

```bash
cosign verify-blob \
  --bundle bundle.json \
  --certificate-identity-regexp \
    "https://github.com/getpanops/nous/.github/workflows/build-bundle.yaml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  nous-YYYY-MM-DD.zip
```

Then apply:

```bash
python3 updater/src/panops-update-intel.py apply nous-YYYY-MM-DD.zip \
  --rules-dir /path/to/rules
```

## SBOM

The SBOM (SPDX-JSON format) is attached to each GitHub Release as `sbom.spdx.json`
and attested on the OCI artifact:

```bash
cosign verify-attestation \
  --type spdxjson \
  --certificate-identity-regexp \
    "https://github.com/getpanops/nous/.github/workflows/build-bundle.yaml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/getpanops/nous:latest
```

## Required network access for online verification

The intel-updater requires egress to:
- `ghcr.io:443` — pull the OCI artifact
- `tuf-repo-cdn.sigstore.dev:443` — Sigstore TUF root for cosign keyless verification
- `fulcio.sigstore.dev:443` — certificate transparency (first-time trust establishment)
- `rekor.sigstore.dev:443` — transparency log verification
