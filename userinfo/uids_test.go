package userinfo_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo"
)

func TestRequireAnyUIDs(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal": {
			have: []string{"user221100", "user567890", "user445566"},
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: []string{"USER221100", "USER567890", "USER445566"},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"substring": {
			have: []string{"user221100XX", "user567890XX", "user445566XX"},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"double": {
			have: []string{"user567890user567890", "user567890098765resu"},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"blank": {
			have: []string{""},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"empty": {
			have: []string{},
			want: userauthz.Decision("User is not in the allow list"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RequireAnyUIDs(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAnyUIDs(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectAnyUIDs(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal": {
			have: []string{"user221100", "user567890", "user445566"},
			want: userauthz.Decision("User is on the deny list"),
		},
		"fold": {
			have: []string{"USER221100", "USER567890", "USER445566"},
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: []string{"user221100XX", "user567890XX", "user445566XX"},
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: []string{"user567890user567890", "user567890098765resu"},
			want: userauthz.DecisionAllow,
		},
		"blank": {
			have: []string{""},
			want: userauthz.DecisionAllow,
		},
		"empty": {
			have: []string{},
			want: userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RejectAnyUIDs(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectAnyUIDs(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}
