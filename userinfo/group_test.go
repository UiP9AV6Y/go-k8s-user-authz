package userinfo_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo"
)

func TestRequireGroup(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have string
		want userauthz.Decision
	}{
		"equal": {
			have: "test",
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: "TEST",
			want: userauthz.Decision("Require membership of \"TEST\""),
		},
		"substring": {
			have: "sometestvalue",
			want: userauthz.Decision("Require membership of \"sometestvalue\""),
		},
		"double": {
			have: "testtest",
			want: userauthz.Decision("Require membership of \"testtest\""),
		},
		"empty": {
			have: "",
			want: userauthz.Decision("Require membership of \"\""),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RequireGroup(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireGroup(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectGroup(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have string
		want userauthz.Decision
	}{
		"equal": {
			have: "test",
			want: userauthz.Decision("Members of \"test\" are not allowed"),
		},
		"fold": {
			have: "TEST",
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: "sometestvalue",
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: "testtest",
			want: userauthz.DecisionAllow,
		},
		"empty": {
			have: "",
			want: userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RejectGroup(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectGroup(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}
