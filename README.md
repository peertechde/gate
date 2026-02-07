# Gate

Gate is a proof‑of‑concept access gateway for Kubernetes, designed to align with zero‑trust principles. It is intentionally opinionated: security first, minimal blast radius, and explicit, auditable access over convenience.

## Why We Built This

Today, access to private clusters usually means a bastion host or a VPN. That comes with familiar problems:

- Long‑lived credentials and unclear revocation paths.
- Scattered audit trails and weak session visibility.
- Infrastructure sprawl (extra hosts, networks, and edge rules).
- “All‑or‑nothing” network access that violates least privilege.

We wanted a simpler, tighter model: short‑lived, explicit access to the Kubernetes API only, with clear session visibility and quick revocation. No broad network tunnels, no generic SSH bastions, just the smallest surface needed to run kubectl.

## What Gate Aims To Be

- Zero‑trust aligned: access is granted explicitly and narrowly.
- Kubernetes‑native: access policies live as CRDs and can be managed via GitOps.
- Auditable by design: sessions are visible and can be terminated.
- Minimal surface area: only the Kubernetes API endpoint is reachable.

## Why We See Potential Here

The combination of GitOps‑managed access grants, short‑lived sessions, and in‑cluster policy enforcement can reduce operational risk without slowing teams down. The goal is to make “least privilege kubectl access” the default instead of the exception.

## Status

Gate is currently a PoC. Expect rough edges, missing features, and opinionated defaults. We are aiming to align with zero‑trust principles, not claiming a full zero‑trust implementation yet. Feedback is welcome.

## What It Is Not

- A general‑purpose bastion or VPN replacement.
- A full audit warehouse or compliance platform.
- A multi‑cluster access orchestrator.

## At A Glance

- SSH access restricted to the Kubernetes API server only.
- SSH public‑key auth with access policies defined by CRDs.
- Optional OIDC SSO device-flow during SSH login (per-user).
- Session visibility and termination via a control API.
- Health endpoints and Prometheus metrics.

## OIDC Device-Flow SSO

Gate can require an OIDC device-flow login in addition to SSH keys. This is enforced per user via the `User` CRD, and relies on OIDC discovery to find the device authorization and token endpoints.

Prerequisites:

- An OIDC provider that supports the device authorization flow (RFC 8628).
- A registered OIDC client (client ID required; client secret optional).
- An ID token that includes a stable subject (`sub`). If you want group enforcement, ensure the ID token includes the desired claim (default: `groups`).
- Gate configured with both `--oidc-issuer-url` and `--oidc-client-id` (both must be set to enable OIDC).

### Gate Configuration

Flags (defaults shown where relevant):

- `--oidc-issuer-url` (required to enable OIDC)
- `--oidc-client-id` (required to enable OIDC)
- `--oidc-client-secret` (optional; confidential clients)
- `--oidc-scopes` (default: `openid,profile,email`)
- `--oidc-group-claim` (default: `groups`)
- `--oidc-device-timeout` (default: `2m`)
- `--oidc-http-timeout` (default: `5s`)

Example:

```sh
gate \
  --oidc-issuer-url https://issuer.example.com \
  --oidc-client-id gate \
  --oidc-client-secret "$GATE_OIDC_CLIENT_SECRET" \
  --oidc-scopes openid,profile,email,groups \
  --oidc-group-claim groups
```

### User CRD Example (Require SSO)

To enforce device-flow login for a user, set `spec.auth.ssoRequired` and bind the user to allowed OIDC subjects (and optional groups):

```yaml
apiVersion: gate.peertech.de/v1alpha1
kind: User
metadata:
  name: alice
  namespace: gate-system
spec:
  userName: alice
  enabled: true
  publicKeys:
  - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForDocs alice@laptop"
  auth:
    ssoRequired: true
  oidc:
    subjects:
    - "00u123abc456def7890"
    groups:
    - "platform"
```

When `ssoRequired` is enabled, Gate will prompt the user with a device code and verification URL during SSH login. Access is granted only if the OIDC subject matches and (if configured) the groups intersect.
