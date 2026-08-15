# Grey Grafana Dashboard

Prometheus dashboard for monitoring Grey JAM node metrics.

## Dashboard Panels

### Block Production
- **Head / Finalized Slot** — Current block height and finality progress
- **Finality Lag** — Slots between head and last finalized block (thresholds: green < 10, yellow < 50, red ≥ 50)
- **Blocks Authored / Imported** — Block production rate

### Consensus
- **GRANDPA Round** — Current finality round
- **Validator Index** — This node's validator index
- **State Transitions** — STF application rate
- **State Transition Duration** — Last STF and block authoring times

### Networking
- **Connected Peers** — P2P peer count
- **Gossip Messages by Topic** — blocks, finality, guarantees, assurances, announcements, tickets
- **Queue Depths** — Event, command, RPC, and pending block queues

### RPC
- **RPC Requests / sec** — Total and per-method request rate
- **RPC Latency (p99)** — 99th percentile latency per method
- **Work Packages** — Submitted and accumulated work packages

### Storage
- **Database Entries** — Blocks, states, DA chunks, GRANDPA votes
- **Store Read / Write Latency** — Storage operation times

### PVM
- **PVM Gas Used** — Gas consumption for accumulation

## Quick Start with Docker Compose

Add the following to your `docker-compose.yml`:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - ./grafana/dashboard.json:/var/lib/grafana/dashboards/dashboard.json
      - ./grafana/dashboards-provider.yaml:/etc/grafana/provisioning/dashboards/dashboards-provider.yaml
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
```

## Prometheus Configuration

Create `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'grey'
    static_configs:
      - targets: ['validator-0:9615']  # Grey metrics port
```

## Import Manually

1. Open Grafana → Dashboards → Import
2. Upload `dashboard.json` or paste JSON
3. Select Prometheus datasource
4. Click Import

## Metrics Reference

The dashboard uses the following metrics exported by Grey:

| Metric | Type | Description |
|--------|------|-------------|
| `grey_block_height` | gauge | Current head slot |
| `grey_finalized_height` | gauge | Last finalized slot |
| `grey_finality_lag` | gauge | Slots between head and finalized |
| `grey_blocks_produced_total` | counter | Blocks authored by this node |
| `grey_blocks_imported_total` | counter | Blocks received and imported |
| `grey_grandpa_round` | gauge | Current GRANDPA round |
| `grey_validator_index` | gauge | This node's validator index |
| `grey_peer_count` | gauge | Connected peers |
| `grey_state_transitions_total` | counter | STF applications |
| `grey_state_transition_last_seconds` | gauge | Last STF duration |
| `grey_block_author_last_seconds` | gauge | Last block authoring duration |
| `grey_store_write_last_seconds` | gauge | Last store write duration |
| `grey_store_read_last_seconds` | gauge | Last store read duration |
| `grey_rpc_requests_total` | counter | Total RPC requests |
| `grey_rpc_requests_by_method` | counter | RPC requests per method |
| `grey_rpc_request_seconds` | histogram | RPC latency histogram |
| `grey_gossipsub_messages_total` | counter | Gossip messages by topic |
| `grey_queue_depth_*` | gauge | Queue depths |
| `grey_pvm_gas_used_total` | counter | PVM gas consumed |
| `grey_work_packages_*` | counter | Work package metrics |
| `grey_stored_*` | gauge | Database entry counts |
