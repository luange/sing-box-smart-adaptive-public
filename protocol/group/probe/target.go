// Package probe contains connectivity targets shared by Smart and AdaptivePool.
package probe

// GoogleConnectivityURL is the stable connectivity signal used for Google
// ecosystem reachability. It intentionally returns no application payload.
const GoogleConnectivityURL = "https://www.google.com/generate_204"
