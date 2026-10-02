# DNS prefill admission and coalescing acceptance

The DNS answer observer publishes advisory routing evidence. A rejected hint is
not a dropped DNS response or packet. DNS Exchange must never wait for prefill.

## Admission contract

- Reject disabled real-DNS paths, answers without usable public addresses, and
  missing route dependencies before occupying one of the two async worker slots.
- Coalesce only work already in flight for the same canonical domain, sorted
  address set, and TTL. A different domain sharing an IP must execute its own
  policy evaluation so proxy evidence can revoke an unsafe DIRECT promotion.
- FakeIP remains authoritative and synchronous. It participates in the Close
  barrier but is not limited by the advisory worker budget.
- TC DNS observations retain their separate bounded drain loop. They share
  in-flight identity with the answer observer without consuming its worker
  slots. Close must wait for both paths before releasing shared state.
- Keep the worker count at two initially. A queue is warranted only if unique
  valid tasks are still rejected under normal production load. If necessary,
  use a bounded queue of at most 16 items with expiry and no DNS Exchange wait.

## Counters and interpretation

All counters are cumulative since process start; compare interval deltas.

| Log field | Meaning |
| --- | --- |
| `dns_prefill_filtered` | Real-DNS answers rejected by feature/address checks |
| `dns_prefill_missing_deps` | Valid real-DNS answers without route dependencies |
| `dns_prefill_coalesced` | In-flight duplicate tasks avoided |
| `dns_prefill_admitted` | Real-DNS async tasks admitted |
| `dns_prefill_queue_drops` | Unique valid advisory tasks rejected by full worker budget |
| `dns_prefill_active`, `dns_prefill_peak` | Current and peak async workers; peak must not exceed 2 |
| `dns_prefill_eval_count`, `dns_prefill_eval_nanos` | Completed policy evaluations and cumulative duration |
| `dns_prefill_eval_le_1ms`, `dns_prefill_eval_le_5ms`, `dns_prefill_eval_le_20ms`, `dns_prefill_eval_gt_20ms` | Exclusive duration buckets for an approximate p95 |

## Required checks

1. Run Linux `with_ebpf` unit tests and one focused race run. Verify duplicate
   bursts, same-IP/different-domain conflict, address ordering, TTL separation,
   FakeIP while both workers are busy, and Close concurrent with admission.
2. On an isolated Linux VM, verify the V3 program loads and the DNS observer
   still runs. A Go compile alone is insufficient for kernel verifier coverage.
3. Record VM115 baseline and new-core metrics under comparable traffic, with
   at least three windows per version. Compare DNS success rate, DNS latency
   p95, process CPU/RSS/goroutines, prefill counter deltas, and V3 map/TC
   errors. Confirm Google 204 and YouTube 200 through the intended proxy path.
4. Observe the new core for 24 hours. Normal traffic should produce no unique
   valid task rejection. If rejections exceed 0.1% of unique valid tasks in a
   continuous five-minute window, investigate policy-evaluation duration and
   implement the bounded second-stage queue.
5. DNS success rate must not fall. DNS p95 must not persist above the baseline
   by more than the larger of 5% or 2 ms under comparable traffic. There must
   be no sustained process CPU/RSS/goroutine regression or increase in V3
   dataplane errors. Keep the raw before/after logs and state the observation
   window; a cumulative drop count alone is not an acceptance result.

Production VM filesystem backups are not part of this workflow. Build artifacts
come from the repository and temporary test binaries are removed after use.
