package usertest_test

import (
	"maps"
	"slices"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo/usertest"
)

func TestMockUserGetName(t *testing.T) {
	tests := map[string]struct {
		have []string
		want string
	}{
		"empty": {
			have: []string{},
			want: usertest.DefaultUserName,
		},
		"single": {
			have: []string{"test"},
			want: "test",
		},
		"multi": {
			have: []string{"test", "case"},
			want: "test",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := usertest.MockUser(test.have)
			got := subject.GetName()

			if got != test.want {
				t.Fatalf("MockUser.GetName() returned %q; expected %q", got, test.want)
			}
		})
	}
}

func TestMockUserGetUID(t *testing.T) {
	tests := map[string]struct {
		have []string
		want string
	}{
		"empty": {
			have: []string{},
			want: "4249001385082748928",
		},
		"single": {
			have: []string{"test"},
			want: "2917332863290441728",
		},
		"multi": {
			have: []string{"test", "case"},
			want: "2917332863290441728",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := usertest.MockUser(test.have)
			got := subject.GetUID()

			if got != test.want {
				t.Fatalf("MockUser.GetUID() returned %q; expected %q", got, test.want)
			}
		})
	}
}

func TestMockUserGetGroups(t *testing.T) {
	tests := map[string]struct {
		have []string
		want []string
	}{
		"empty": {
			have: []string{},
			want: []string{},
		},
		"single": {
			have: []string{"test"},
			want: []string{"test"},
		},
		"multi": {
			have: []string{"test", "case"},
			want: []string{"test", "case"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := usertest.MockUser(test.have)
			got := subject.GetGroups()

			if !compareStrings(got, test.want) {
				t.Fatalf("MockUser.GetGroups() returned %q; expected %q", got, test.want)
			}
		})
	}
}

func TestMockUserGetExtra(t *testing.T) {
	tests := map[string]struct {
		have []string
		want []string
	}{
		"empty": {
			have: []string{},
			want: []string{},
		},
		"single": {
			have: []string{"test"},
			want: []string{"test"},
		},
		"multi": {
			have: []string{"test", "case"},
			want: []string{"test", "case"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := usertest.MockUser(test.have)
			got := subject.GetExtra()

			if len(got) != 1 {
				t.Fatalf("MockUser.GetExtra() returned key set %v; expected map of one", maps.Keys(got))
			}

			gotValues, ok := got[usertest.MockExtraKey]
			if !ok {
				t.Fatalf("MockUser.GetExtra() returned key set %v; expected %q", maps.Keys(got), usertest.MockExtraKey)
			}

			if !compareStrings(gotValues, test.want) {
				t.Fatalf("MockUser.GetExtra() returned %q; expected %q", gotValues, test.want)
			}
		})
	}
}

func compareStrings(l, r []string) bool {
	if len(l) != len(r) {
		return false
	}

	for _, g := range r {
		if !slices.Contains(l, g) {
			return false
		}
	}

	return true
}
