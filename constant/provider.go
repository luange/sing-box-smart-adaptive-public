package constant

const (
	ProviderTypeInline    = "inline"
	ProviderTypeLocal     = "local"
	ProviderTypeRemote    = "remote"
	ProviderTypeAggregate = "aggregate"
)

func ProviderDisplayName(providerType string) string {
	switch providerType {
	case ProviderTypeInline:
		return "Inline"
	case ProviderTypeLocal:
		return "Local"
	case ProviderTypeRemote:
		return "Remote"
	case ProviderTypeAggregate:
		return "Aggregate"
	default:
		return "Unknown"
	}
}
