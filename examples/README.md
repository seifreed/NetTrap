# NetTrap Integration Examples

Ready-to-run Docker Compose stacks for testing NetTrap with event sinks and
deployment modes. Database storage currently supports SQLite and PostgreSQL.

## Quick Start

Each example runs from the project root:

```bash
# From the NetTrap root directory
docker compose -f examples/docker-compose.<integration>.yml up -d
```

## Available Integrations

### Elasticsearch + Kibana
```bash
docker compose -f examples/docker-compose.elasticsearch.yml up -d

# Access:
#   Kibana:    http://localhost:5601
#   ES API:    http://localhost:9200
#   Honeypot:  http://localhost:18080 (HTTP), port 12222 (SSH), port 12323 (Telnet)
#   Health:    http://localhost:9091/health
#   Metrics:   http://localhost:9091/metrics

# Test:
curl http://localhost:18080/test
curl http://localhost:9200/nettrap-events/_count

# Cleanup:
docker compose -f examples/docker-compose.elasticsearch.yml down -v
```

**Tested: 3 events indexed and searchable in Elasticsearch**

### Kafka (Redpanda) + Console
```bash
docker compose -f examples/docker-compose.kafka.yml up -d

# Access:
#   Redpanda Console: http://localhost:8888
#   Kafka API:        localhost:19092
#   Honeypot:         http://localhost:18080 (HTTP)
#   Health:           http://localhost:9091/health

# Cleanup:
docker compose -f examples/docker-compose.kafka.yml down -v
```

### Syslog (RFC 5424)
```bash
docker compose -f examples/docker-compose.syslog.yml up -d

# Access:
#   Honeypot:  http://localhost:18080 (HTTP)
#   Health:    http://localhost:9091/health

# View syslog messages:
docker logs nettrap-syslog

# Cleanup:
docker compose -f examples/docker-compose.syslog.yml down -v
```

**Tested: RFC 5424 formatted syslog messages received via UDP**

### Splunk (Free License)
```bash
docker compose -f examples/docker-compose.splunk.yml up -d

# Access:
#   Splunk Web: http://localhost:8000 (admin/changeme123)
#   Honeypot:   http://localhost:18080 (HTTP)
#   Health:     http://localhost:9091/health

# Note: Splunk takes ~2 minutes to start
# Cleanup:
docker compose -f examples/docker-compose.splunk.yml down -v
```

### Multi-Node Fleet (3 nodes + TCP collector)
```bash
docker compose -f docker-compose.test.yml up -d

# 3 NetTrap nodes with different configs:
#   Node 1 (us-east-1): DNS, HTTP, SSH, Telnet
#   Node 2 (eu-west-1): DNS, HTTP, SSH, Telnet
#   Node 3 (ap-southeast-1): DNS, HTTP, Redis, MySQL

# Health:
curl http://localhost:9091/health  # Node 1
curl http://localhost:9092/health  # Node 2
curl http://localhost:9093/health  # Node 3

# Cleanup:
docker compose -f docker-compose.test.yml down -v
```

**Tested: 15 events collected centrally from 3 nodes in 3 regions**

## Event Sink Configuration

All examples use the `[distributed]` config section:

```toml
[distributed]
enabled = true
health_bind = "0.0.0.0:9090"

# Elasticsearch
[[distributed.event_sinks]]
type = "http"
target = "http://elasticsearch:9200/nettrap-events/_doc"
batch_size = 1

# Kafka/Logstash/Fluentd (TCP JSON lines)
[[distributed.event_sinks]]
type = "tcp"
target = "logstash:5044"

# Syslog (RFC 5424 UDP)
[[distributed.event_sinks]]
type = "syslog"
target = "syslog-server:514"

# Splunk HEC
[[distributed.event_sinks]]
type = "http"
target = "https://splunk:8088/services/collector/event"
auth = "Splunk your-hec-token"

# Generic webhook
[[distributed.event_sinks]]
type = "http"
target = "https://your-api.com/webhook"
auth = "Bearer your-token"
```

## Standalone Mode

Without `[distributed]`, NetTrap runs as a standalone honeypot:

```bash
./target/release/nettrap run -c config.toml
```

No external dependencies required.
