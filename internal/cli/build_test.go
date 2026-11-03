package cli

import "testing"

func TestMatchingReleaseArtifactsIgnoreDateButCheckCommit(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"0.30.0 (abcdef1234567, yesterday)", "0.30.0 (abcdef1, today)", true},
		{"v0.30.0", "0.30.0 (abcdef1, today)", true},
		{"0.30.0 (abcdef1, today)", "0.30.0 (fedcba9, today)", false},
		{"0.29.9", "0.30.0", false},
		{"dev (abcdef1, yesterday)", "dev (abcdef1, today)", false},
		{"", "", false},
		{"dev", "dev", true},
	} {
		if got := sameHelperBuild(tc.a, tc.b); got != tc.same {
			t.Errorf("%q vs %q: got %v", tc.a, tc.b, got)
		}
	}
}
