# LoadBalance identity and UDP isolation audit

The previous sticky-session implementation stored a member slice index in its
LRU. Provider refreshes replace and reorder that slice, so a still-in-range
index could silently select a different endpoint. Sticky entries now store the
versioned `SelectedRecord` used by the rest of the group code. Runtime sticky
lookup is credential-sensitive: when a record has a `DialIdentity`, only that
exact authenticated member is accepted. If it has disappeared, the entry is
treated as a miss and the strategy selects a new member. `EndpointIdentity`/tag
fallback remains available only for old static records that do not carry a dial
identity; it can no longer silently migrate a provider session to another
credential on the same path.

LoadBalance and URLTest also had a transport-isolation violation: a failed UDP
`ListenPacket` deleted the member's TCP URL-test history. UDP failures now use a
bounded, 30-second, identity-keyed passive ledger. A successful UDP open clears
that entry; TCP history is never deleted by a UDP failure. The short cooldown
prevents immediate retry storms without turning one destination's transient
UDP failure into a permanent node quarantine.

Regression coverage verifies sticky identity remapping after member reorder,
strict credential miss/reselection, UDP-only suppression, and preservation of
TCP history. The tracker stores only opaque identities and timestamps, so
provider refreshes cannot retain outbound objects.
