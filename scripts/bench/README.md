# Data-plane benchmark methodology (audit point #28)

The claim "the TC dataplane is faster" is only meaningful against the right
baseline: **official sing-box with TUN + auto_redirect + route_exclude_address_set**,
not a bare TUN setup. This directory contains a harness that runs that
comparison on one host so results are apples-to-apples.

## What it measures

| Metric | Source | Why |
| --- | --- | --- |
| latency p50/p95/p99 | `curl %time_total` × N via the local proxy inbound | user-visible first-request latency |
| sing-box CPU % | `/proc/<pid>/stat` utime+stime over the measured window | per-byte/per-packet driver cost |
| throughput | iperf3 through the proxy inbound (optional, needs an iperf3 host) | proxy path ceiling |

## Traffic models

- `TRAFFIC_MODEL=proxy` — everything goes through the proxy group (all-proxy
  deployments; the kernel bypass contributes nothing here by design).
- `TRAFFIC_MODEL=direct` — requests bypass the proxy inbound and hit the
  dataplane's DIRECT path. This is the model where TC/LPM offload vs
  auto_redirect actually differ; run both models and compare each against
  its own baseline.

## Requirements / fairness rules

1. Same host, same kernel, same node pool, back-to-back alternating rounds
   (A,B,A,B) so network drift averages out.
2. Both configs must expose the same inbound on the same port and select the
   same upstream. Only the dataplane (transport) differs.
3. Restart between candidates; warm-up window excludes cold-start compilation
   (eBPF load) and TLS session establishment.
4. Run at least 3 rounds; report p50/p95/p99, never a single mean.
5. Record build tags from `sing-box version` for both binaries in the report.

## Known limits of this harness

- CPU% uses an approximated measurement window (latency + throughput phases).
- It does not measure PPS saturation or conntrack pressure; extend with
  `pktgen`/`moonpack` if that matters for your deployment.
- DIRECT-model comparisons must pin the destination set (CN IP list or your
  bypass rule-set) so both candidates offload the same addresses.

Run it on a test host or a maintenance window; the harness restarts the
sing-box process between candidates.
