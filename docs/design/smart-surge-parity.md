# Smart Surge Behavioral Parity

This document defines a clean-room behavioral target for Smart based on the
reverse-engineering notes for Surge for Mac 6.9.0. It is a behavioral
specification, not a source-code port. Existing repository code and tests remain
the authority for sing-box lifecycle, endpoint identity, dialing, and safety.

## Decision Contract

For each request, filter candidates that cannot serve the requested transport
or have an authoritative undetectable protocol error. Score the remaining
candidates using the Surge model: first-response delay plus packet-loss ratio
times 5000, adjusted by the candidate priority. A missing delay is score zero.

Split candidates into A/B/C bands relative to the best positive score, using
50 ms times the best candidate's priority adjustment. Failed URL tests place an
otherwise out-of-band candidate in C. A real failure for the current registered
domain demotes that candidate from A to B for one hour; a successful connection
to that same domain clears its stain. TCP and UDP have separate site records.

Randomize within each band, then concatenate A, B, and C. Promote the site's
best successful candidate when its sample is credible: either successful-site
coverage reaches 70% of the eligible candidates, or its adjusted delay is
within `minScore + adjBest * (successCount² * 40 + 50)`.

## Host Integration Boundaries

- The host owns transport capability filtering, site identity, actual dial and
  failover, URL-test result ingestion, and endpoint identity.
- Smart policy state owns per-site success/failure records and the returned
  ordered candidate list; a single persistent group-primary FSM must not
  overwrite that order.
- A successful real connection clears only that candidate's failure stain for
  the same site and transport. It also resets any cross-site escalation window
  accumulated for that candidate.
- Dashboard/manual probes are observational; they may update probe history but
  cannot claim a successful data-plane connection or mutate site affinity.
- Keep sing-box-specific hard protocol failure handling, cancellation
  exclusion, bounded retries, and fail-open behavior where they prevent unsafe
  routing. These are explicit safety extensions, not Surge parity claims.

## Acceptance Tests

Cover score math and priority adjustment; exact A/B/C boundaries; untested
candidate exploration; randomization confined to a band; site affinity with
and without the 70% gate; one-hour stain expiry and same-site success clearing;
TCP/UDP isolation; URL-test failure placement; provider reload identity
stability; manual pin behavior; and ordered real-dial failover. Tests must assert
the candidate actually dialed, not only an internal selected tag.
