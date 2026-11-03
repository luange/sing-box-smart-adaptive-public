//go:build with_connection_history

package connectionhistory

import "testing"

func TestRecordMatchesQueryStructuredFilters(t *testing.T) {
	record := Record{
		SourceIP: "192.168.0.30", Inbound: "tproxy", Network: "tcp", Outbound: "proxy",
		Chain: []string{"group", "leaf"}, Rule: "rule-a", Domain: "api.example.com",
		DestinationIP: "203.0.113.7", CloseReason: "timeout", Process: "browser",
	}
	query := Query{
		SourceIP: "192.168.0.30", Inbound: "tproxy", Network: "tcp", Outbound: "group > leaf",
		Rule: "rule-a", Domain: "example.com", DestinationIP: "203.0.113.7", CloseReason: "timeout",
	}
	if !recordMatchesQuery(record, query) {
		t.Fatal("record should match all supplied filters")
	}
	query.CloseReason = "completed"
	if recordMatchesQuery(record, query) {
		t.Fatal("record unexpectedly matched a different close reason")
	}
}

func TestAggregateMatchesSupportedFiltersAndRejectsDetailedOnlyFields(t *testing.T) {
	item := aggregate{Domain: "api.example.com", IP: "203.0.113.7", Source: "192.168.0.30", Outbound: "group > leaf", Rule: "rule-a"}
	query := Query{SourceIP: "192.168.0.30", Outbound: "group > leaf", Domain: "example.com", Search: "rule-a"}
	if !aggregateMatchesQuery(item, query) {
		t.Fatal("aggregate should match dimensions represented by stored aggregate fields")
	}
	query.CloseReason = "timeout"
	if aggregateMatchesQuery(item, query) {
		t.Fatal("aggregate must reject filters that it does not store")
	}
}
