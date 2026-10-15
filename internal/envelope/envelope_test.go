package envelope

import "testing"

func TestDecodeStrict(t *testing.T) {
	var v map[string]any
	for _, bad := range []string{`{"a":1}]`, `{"a":1}}`, `{"a":1}{"b":2}`, `{"a":1} x`} {
		if err := DecodeStrict([]byte(bad), &v); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if err := DecodeStrict([]byte(" {\"a\":1} \n"), &v); err != nil {
		t.Errorf("rejected surrounding whitespace: %v", err)
	}
	type s struct{ A int }
	var x s
	if err := DecodeStrict([]byte(`{"A":1,"B":2}`), &x); err == nil {
		t.Error("accepted an unknown field")
	}
}
