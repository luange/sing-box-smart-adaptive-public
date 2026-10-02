# Provider manager and Smart generation audit

## Findings

The provider manager previously committed `started/stage` before all provider
start hooks completed. A later failure left earlier providers running and made
the next retry panic. The same operation mutex also covered external lifecycle
hooks and update callbacks, so a provider or observer that re-entered the
manager could self-deadlock. Replacement cleanup errors were returned after a
new provider had already been published, which made callers retry an operation
that had actually succeeded.

Smart candidate rebuilding validated the provider revision before flattening,
identity construction, and ranking metadata were complete. A callback could
advance the revision in that interval and the old catalog could still be
published once before the trailing rebuild.

## Remediation

Manager transitions now reserve state, run external hooks without the operation
mutex, and commit only after success. Failed starts close every attempted
provider in reverse order and restore the previous lifecycle state. Create,
Remove, and Close mutations are rejected while a start transaction is active;
callers can retry after the transaction completes, so no provider can be
published without its start hook or be closed and then started again. Provider
cleanup uses a short-lived in-flight table rather than retaining every closed
provider. Manager callbacks are always notified after releasing transition
locks, and replacement cleanup failures are warnings because publication is
already authoritative. Create also checks the manager generation before commit,
so a concurrent Close cannot repopulate a closed manager.

Smart performs a final provider-set/revision check while holding
`providerAccess` across the catalog publish lock. A newer provider generation
therefore cannot be published from an older snapshot.

## Verification

```sh
go test ./adapter/provider ./protocol/group
go test -race ./adapter/provider ./protocol/group
go vet ./adapter/provider ./protocol/group
go test ./...
```

The tests include partial-start rollback/retry and callback re-entry. Linux
release and audit workflows remain the required cross-platform build gate.
