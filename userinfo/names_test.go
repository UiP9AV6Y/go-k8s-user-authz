package userinfo_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo"
)

func TestRequireAnyNames(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal": {
			have: []string{"foo", "mock", "gaff"},
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: []string{"foo", "MOCK", "gaff"},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"substring": {
			have: []string{"foo", "testmockdouble", "gaff"},
			want: userauthz.Decision("User is not in the allow list"),
		},
		"double": {
			have: []string{"foo", "mockmock", "gaff"},
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
			subject := userinfo.RequireAnyNames(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAnyNames(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectAnyNames(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal": {
			have: []string{"foo", "mock", "gaff"},
			want: userauthz.Decision("User is on the deny list"),
		},
		"fold": {
			have: []string{"foo", "MOCK", "gaff"},
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: []string{"foo", "testmockdouble", "gaff"},
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: []string{"foo", "mockmock", "gaff"},
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
			subject := userinfo.RejectAnyNames(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectAnyNames(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}
