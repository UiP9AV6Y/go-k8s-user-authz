package userauthz_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

func TestRequireName(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have string
		want userauthz.Decision
	}{
		"equal": {
			have: "mock",
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: "MOCK",
			want: userauthz.Decision("User \"MOCK\" is required"),
		},
		"substring": {
			have: "testmockdouble",
			want: userauthz.Decision("User \"testmockdouble\" is required"),
		},
		"double": {
			have: "mockmock",
			want: userauthz.Decision("User \"mockmock\" is required"),
		},
		"empty": {
			have: "",
			want: userauthz.Decision("User \"\" is required"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.RequireName(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireName(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectName(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have string
		want userauthz.Decision
	}{
		"equal": {
			have: "mock",
			want: userauthz.Decision("User \"mock\" is not allowed"),
		},
		"fold": {
			have: "MOCK",
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: "testmockdouble",
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: "mockmock",
			want: userauthz.DecisionAllow,
		},
		"empty": {
			have: "",
			want: userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.RejectName(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectName(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}
