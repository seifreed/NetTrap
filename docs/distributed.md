# Distributed Deployment Guide

NetTrap supports distributed deployment where multiple honeypot nodes report to a central system. **Distributed features are entirely optional** — standalone mode works with zero distributed config.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Control Plane                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Config   │  │ Fleet    │  │ Alert    │  │ Dashboard  │  │
│  │ Server   │  │ Manager  │  │ Engine   │  │ (Kibana)   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬───────┘  │
│       └──────────────┴──────────────┴──────────────┘         │
│                       REST/gRPC API                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
    ┌─────────▼──┐ ┌──────▼────┐ ┌───▼──────────┐
    │  NetTrap   │ │  NetTrap  │ │  NetTrap     │
    │  Node #1   │ │  Node #2  │ │  Node #N     │
    │  (AWS)     │ │  (Azure)  │ │  (On-prem)   │
    └────────────┘ └───────────┘ └──────────────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
    ┌─────────▼──┐ ┌──────▼────┐ ┌───▼──────────┐
    │Elasticsearch│ │  Splunk  │ │  S3/MinIO    │
    │ (search)    │ │ (SIEM)   │ │  (PCAP store)│
    └─────────────┘ └──────────┘ └──────────────┘
```

## Enabling Distributed Mode

Add the `[distributed]` section to your `config.toml`:

```toml
[distributed]
enabled = true
node_region = "us-east-1"
node_tags = ["honeypot", "production", "aws"]

# Health check endpoint (required for K8s liveness/readiness probes)
health_bind = "0.0.0.0:9090"

# Heartbeat to control plane (optional)
heartbeat_interval_secs = 30
control_plane_url = "https://control.your-domain.com"
control_plane_token = "your-api-token-here"
```

## Event Sinks

Events are shipped in real-time to one or more external systems. Multiple sinks can be active simultaneously.

### Elasticsearch / OpenSearch

```toml
[[distributed.event_sinks]]
type = "http"
target = "https://elasticsearch:9200/nettrap-events/_bulk"
auth = "Basic ZWxhc3RpYzpwYXNzd29yZA=="
batch_size = 100
```

### Splunk HEC (HTTP Event Collector)

```toml
[[distributed.event_sinks]]
type = "http"
target = "https://splunk:8088/services/collector/event"
auth = "Splunk your-hec-token"
batch_size = 50
```

### Logstash / Fluentd (TCP JSON)

```toml
[[distributed.event_sinks]]
type = "tcp"
target = "logstash:5044"
```

### Syslog (RFC 5424 over UDP)

```toml
[[distributed.event_sinks]]
type = "syslog"
target = "syslog-server:514"
```

### Custom Webhook

```toml
[[distributed.event_sinks]]
type = "http"
target = "https://your-api.com/webhook/nettrap"
auth = "Bearer your-token"
batch_size = 10
```

## Health Checks & Metrics

When `health_bind` is configured, NetTrap exposes:

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness check — returns node status, ID, uptime |
| `GET /ready` | Readiness check — returns ready state |
| `GET /metrics` | Prometheus-compatible metrics |

### Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'nettrap'
    static_configs:
      - targets: ['nettrap-node1:9090', 'nettrap-node2:9090']
    metrics_path: '/metrics'
```

## Node Identity

Each node automatically generates a unique `node_id` (UUID) on startup. The node identity includes:

- `node_id` — Unique UUID per instance
- `hostname` — System hostname
- `region` — Configurable region tag
- `tags` — Arbitrary labels for fleet management
- `started_at` — ISO 8601 timestamp

This identity is included in:
- Every NBI event sent to sinks
- Heartbeat messages to the control plane
- Health check responses
- Prometheus metrics labels

## Multi-Node Docker Compose

For local testing with multiple nodes:

```bash
# Start a 2-node cluster with Elasticsearch + Kibana
docker-compose up -d

# View node1 health
curl http://localhost:9091/health

# View node2 health
curl http://localhost:9092/health

# Query events in Elasticsearch
curl http://localhost:9200/nettrap-events/_search?pretty

# Open Kibana dashboard
open http://localhost:5601
```

## Scaling

### Horizontal Scaling

Each NetTrap node is stateless (except local PCAP files). Scale by adding more nodes:

```bash
# Scale with Docker Compose
docker-compose up -d --scale nettrap-node1=5

# Scale with Kubernetes
kubectl scale deployment nettrap --replicas=10
```

### Port Allocation Strategy

For multiple nodes on the same host, use different port mappings:

| Node | DNS | HTTP | LDAP | SSH | Telnet | Metrics |
|------|-----|------|------|-----|--------|---------|
| 1 | 5353 | 8080 | 1389 | 2222 | 2323 | 9091 |
| 2 | 5354 | 8081 | 1389 | 2223 | 2324 | 9092 |
| 3 | 5355 | 8082 | 1389 | 2224 | 2325 | 9093 |

### Cloud Auto-Scaling

Use cloud-native auto-scaling based on Prometheus metrics:

```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: nettrap
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nettrap
  minReplicas: 2
  maxReplicas: 20
  metrics:
  - type: Pods
    pods:
      metric:
        name: nettrap_connections_total
      target:
        type: AverageValue
        averageValue: "100"
```

## Security Considerations

1. **Network isolation** — Deploy honeypot nodes in isolated VLANs/VPCs
2. **API authentication** — Always use tokens for control plane communication
3. **TLS everywhere** — Use HTTPS for event sinks and control plane
4. **RBAC** — Limit who can access the control plane and metrics
5. **PCAP storage** — Encrypt at rest, rotate regularly
6. **Node hardening** — Run as non-root where possible (requires CAP_NET_ADMIN for packet capture)

## Troubleshooting

### Events not appearing in Elasticsearch

1. Check sink connectivity: `curl -X POST http://elasticsearch:9200/test/_doc -d '{"test":true}'`
2. Check NetTrap logs: `docker logs nettrap-node1 | grep "sink"`
3. Verify config: `nettrap config --check -c config.toml`

### Heartbeat failures

1. Verify control plane URL is reachable
2. Check token is valid
3. Look for `Heartbeat failed` in logs

### High memory usage

1. Reduce `batch_size` in HTTP sinks
2. Enable PCAP rotation with `pcap_prefix`
3. Reduce number of active listeners
