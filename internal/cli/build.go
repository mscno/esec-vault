package cli

import (
	"regexp"
	"strings"
)

var releaseVersion = regexp.MustCompile(`^v?([0-9]+\.[0-9]+\.[0-9]+)$`)

// sameHelperBuild accepts separately built artifacts of the same release.
// The Mac bundle uses a short commit, GoReleaser a full commit and each has a
// different build timestamp. A go-install release may omit commit metadata.
// Development builds keep the existing exact comparison.
func sameHelperBuild(a, b string) bool {
	if a == b {
		return a != ""
	}
	av, am, _ := strings.Cut(a, " (")
	bv, bm, _ := strings.Cut(b, " (")
	at, bt := releaseVersion.FindStringSubmatch(av), releaseVersion.FindStringSubmatch(bv)
	if len(at) != 2 || len(bt) != 2 || at[1] != bt[1] {
		return false
	}
	ac, _, _ := strings.Cut(strings.TrimSuffix(am, ")"), ",")
	bc, _, _ := strings.Cut(strings.TrimSuffix(bm, ")"), ",")
	if ac == "" || bc == "" {
		return true
	}
	return len(ac) >= 7 && len(bc) >= 7 && (strings.HasPrefix(ac, bc) || strings.HasPrefix(bc, ac))
}
