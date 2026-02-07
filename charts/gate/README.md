# Gate Helm Chart

This chart deploys the Gate service into a Kubernetes cluster. Gate provides SSH-based access to the Kubernetes API server through a restricted TCP tunnel and exposes an HTTP control API for session visibility.

## Prerequisites

- Kubernetes 1.24+
- Helm 3
- Gate User CRD installed (this chart ships the CRD in `crds/`)

## Install

1. Create a namespace (example: `gate-system`).
2. Create the SSH host key Secret (recommended: pre-created, no bootstrap).
3. Install the chart.

### Create the host key Secret

```sh
ssh-keygen -t ed25519 -f ssh_host_key -N ""
kubectl -n gate-system create secret generic gate-host-key \
  --from-file=ssh_host_key=./ssh_host_key
```

### Install the chart

```sh
helm install gate charts/gate \
  -n gate-system --create-namespace \
  --set image.repository=peertech/gate \
  --set image.tag=YOUR_TAG
```

## Configuration

Key values (see `values.yaml` for full list):

- `image.repository`, `image.tag`: container image
- `ssh.service.type`: defaults to `LoadBalancer`
- `http.service.type`: defaults to `ClusterIP`
- `config.hostKeySecretName`, `config.hostKeySecretKey`, `config.hostKeyNamespace`
- `config.userNamespace`: namespace to watch for User CRDs
- `limits.maxConcurrentSessions`, `limits.maxSessionDuration` (`0s` disables enforcement)
- `oidc.issuerURL`, `oidc.clientID`, `oidc.clientSecret`, `oidc.scopes`, `oidc.groupClaim`

### User CRD Namespace

Gate watches the namespace defined by `config.userNamespace`. If you set a namespace different from the release namespace, this chart will create an additional Role/RoleBinding in that namespace to allow CRD reads.

### NetworkPolicy (optional)

Enable with:

```sh
helm upgrade --install gate charts/gate \
  -n gate-system \
  --set networkPolicy.enabled=true \
  --set networkPolicy.sshIngressCIDRs={"10.0.0.0/8"}
```

## Rollout / Rollback

- Rollout: `helm upgrade --install gate charts/gate ...`
- Rollback: `helm rollback gate <revision>` or `kubectl rollout undo deployment/gate`

## Notes

- The HTTP service is internal by default (ClusterIP). If you expose it externally, place it behind an OIDC proxy.
- CRDs in `crds/` are installed on first install. Helm does not automatically update CRDs on upgrade; review CRD changes manually.
