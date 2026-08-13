# Kubernetes Deployment

## Prerequisites

- Kubernetes cluster (1.24+)
- kubectl configured
- Container registry access

## Quick Deploy

```bash
# Create namespace
kubectl apply -f deploy/kubernetes/namespace.yaml

# Deploy config
kubectl apply -f deploy/kubernetes/configmap.yaml -n nettrap

# Deploy NetTrap
kubectl apply -f deploy/kubernetes/deployment.yaml -n nettrap
kubectl apply -f deploy/kubernetes/service.yaml -n nettrap

# Verify
kubectl get pods -n nettrap
kubectl get svc -n nettrap
```

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

## Scaling

```bash
# Manual scaling
kubectl scale deployment nettrap --replicas=5 -n nettrap

# Auto-scaling (requires metrics-server)
kubectl autoscale deployment nettrap --min=2 --max=20 --cpu-percent=50 -n nettrap
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
