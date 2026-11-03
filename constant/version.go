package constant

var Version = "unknown"

// Revision is injected by release builds.  Keep it separate from Version so
// operators can compare an immutable source commit without parsing a display
// version string.
var Revision string
