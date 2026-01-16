# FortiWeb CRD Controller

Custom Kubernetes controller for managing FortiWeb WAF configuration via CRDs.

## Overview

This controller replaces the official FortiWeb Ingress Controller with a custom implementation that:
- Supports single policy with multiple content routing rules (official IC creates one policy per ingress)
- Handles cross-namespace backend services via ExternalName service resolution
- Automatically wires all content routing rules into the policy
- Provides full GitOps control over FortiWeb configuration

## Why This Controller?

The official FortiWeb Ingress Controller has limitations:
1. Creates one virtual server/policy per Ingress - can't share VIP:port across apps
2. Doesn't support ExternalName services for cross-namespace routing
3. Doesn't wire content routing rules when adding to existing policies

This controller solves all three issues by managing the complete FortiWeb configuration as a single resource.

## Quick Start

```bash
# 1. Install the CRD
kubectl apply -f crds/fortiwebingress.yaml

# 2. Deploy the controller
kubectl apply -k deploy/

# 3. Create a FortiWebIngress resource
kubectl apply -f examples/gateway.yaml
```

## CRD Reference

### FortiWebIngress

```yaml
apiVersion: fortiweb.40docs.com/v1
kind: FortiWebIngress
metadata:
  name: gateway
  namespace: fortiweb-system
spec:
  # FortiWeb appliance connection
  fortiweb:
    address: "10.0.10.100:8443"          # FortiWeb management IP:port
    credentialsSecret: fortiweb-creds     # Secret with username/password
    credentialsSecretNamespace: default   # Optional, defaults to CR namespace

  # Virtual server configuration
  virtualServer:
    name: gateway                         # Optional, defaults to CR name
    ip: "10.0.1.100"                     # VIP address
    interface: port1                      # Network interface
    useInterfaceIP: true                 # Use interface IP instead of dedicated VIP

  # Server policy configuration
  policy:
    name: gateway-policy                  # Optional, defaults to CR name
    webProtectionProfile: "Inline Standard Protection"
    httpService: "HTTP"
    httpsService: "HTTPS"
    synCookie: "enable"
    httpToHttps: "disable"

  # Content routing rules
  routes:
    - host: shop.40docs.com
      path: /                            # Optional, defaults to /
      backend:
        serviceName: frontend
        serviceNamespace: online-boutique # Cross-namespace supported
        port: 80
      tls:                               # Optional TLS config
        enabled: false
        secretName: shop-tls

    - host: xperts.40docs.com
      backend:
        serviceName: xperts
        serviceNamespace: xperts
        port: 8080
```

### Status

The controller updates the CR status with created resources:

```yaml
status:
  state: Ready                    # Pending, Syncing, Ready, Error
  message: "Successfully reconciled"
  virtualServer: gateway
  policy: gateway-policy
  serverPools:
    - gateway-pool-r0
    - gateway-pool-r1
  contentRoutingRules:
    - gateway-cr-r0
    - gateway-cr-r1
```

## Project Structure

```
fortiweb_crds/
├── README.md
├── Dockerfile
├── requirements.txt
├── crds/                        # CRD definitions
│   └── fortiwebingress.yaml
├── controller/                  # Controller source code
│   ├── __init__.py
│   ├── main.py                  # kopf handlers
│   └── fortiweb_client.py       # FortiWeb REST API client
├── deploy/                      # Kubernetes manifests
│   ├── namespace.yaml
│   ├── rbac.yaml
│   ├── deployment.yaml
│   └── kustomization.yaml
└── examples/
    └── gateway.yaml             # Example FortiWebIngress
```

## How It Works

When a FortiWebIngress CR is created/updated:

1. **Virtual Server**: Creates a FortiWeb virtual server with the specified VIP
2. **Server Pools**: For each route, resolves the K8s service to endpoints and creates a server pool
3. **Content Routing**: Creates content routing policies with host/path matching
4. **Policy**: Creates server policy and **wires all content routing rules** into it

When deleted, resources are cleaned up in reverse order.

### Cross-Namespace Service Resolution

The controller automatically resolves services across namespaces:

```yaml
routes:
  - host: app.example.com
    backend:
      serviceName: my-service        # Service in different namespace
      serviceNamespace: other-ns     # Controller resolves endpoints directly
      port: 8080
```

This works because the controller reads the Endpoints resource directly, bypassing the ExternalName limitation of the official IC.

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (requires kubeconfig with cluster access)
cd controller
kopf run main.py --verbose

# Build container
docker build -t fortiweb-controller:latest .

# Push to registry
docker tag fortiweb-controller:latest your-registry/fortiweb-controller:latest
docker push your-registry/fortiweb-controller:latest
```

## Credentials Secret

Create a secret with FortiWeb credentials:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fortiweb-credentials
  namespace: fortiweb-system
type: Opaque
stringData:
  username: admin
  password: your-password
```

Or with External Secrets Operator:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: fortiweb-credentials
  namespace: fortiweb-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: ClusterSecretStore
  target:
    name: fortiweb-credentials
  data:
    - secretKey: username
      remoteRef:
        key: dev/fortiweb
        property: username
    - secretKey: password
      remoteRef:
        key: dev/fortiweb
        property: password
```

## Tech Stack

- Python 3.11+
- [kopf](https://kopf.readthedocs.io/) - Kubernetes Operator Framework
- [kubernetes](https://github.com/kubernetes-client/python) - Python K8s client
- [httpx](https://www.python-httpx.org/) - HTTP client for FortiWeb API
- [pydantic](https://docs.pydantic.dev/) - Data validation
