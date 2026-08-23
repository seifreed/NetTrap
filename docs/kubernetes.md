# Kubernetes Deployment

## Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- A NetTrap release OCI digest from `nettrap-oci-image.txt`

## Quick Deploy

```bash
# Download nettrap-oci-image.txt and nettrap-kubernetes-deployment.yaml
# from the same GitHub release. The generated deployment is pinned to
# the multi-architecture image digest recorded in the text file.

# Create namespace
kubectl apply -f deploy/kubernetes/namespace.yaml

# Deploy config
kubectl apply -f deploy/kubernetes/configmap.yaml -n nettrap

# Deploy NetTrap
kubectl apply -f nettrap-kubernetes-deployment.yaml -n nettrap
kubectl apply -f deploy/kubernetes/service.yaml -n nettrap

# Verify
kubectl get pods -n nettrap
kubectl get svc -n nettrap
```

The checked-in deployment contains a non-existent zero digest so it fails closed.
Release automation replaces it with the published GHCR manifest digest. For a
private mirror, replace the generated `image` value with the mirror's digest,
never a mutable tag.

## Verify Health

```bash
# Port-forward metrics endpoint
kubectl port-forward svc/nettrap-metrics 9090:9090 -n nettrap

# Check health
curl http://localhost:9090/health
curl http://localhost:9090/metrics
```

## View Logs

```bash
kubectl logs -f deployment/nettrap -n nettrap
```

## Custom Configuration

Edit the ConfigMap:
```bash
kubectl edit configmap nettrap-config -n nettrap
# Then restart pods to pick up changes:
kubectl rollout restart deployment/nettrap -n nettrap
```

## Exposing to Internet

For real honeypot deployment, use a LoadBalancer or NodePort service:

```bash
# Get external IP
kubectl get svc nettrap -n nettrap -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

## Cleanup

```bash
kubectl delete namespace nettrap
```
