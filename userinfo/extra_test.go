package userinfo_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo"
)

func TestRequireExtra(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		haveKey   string
		haveValue string
		want      userauthz.Decision
	}{
		"equal": {
			haveKey:   mockExtraKey,
			haveValue: "test",
			want:      userauthz.DecisionAllow,
		},
		"fold": {
			haveKey:   mockExtraKey,
			haveValue: "TEST",
			want:      userauthz.Decision("Extra values does not contain \"TEST\""),
		},
		"substring": {
			haveKey:   mockExtraKey,
			haveValue: "sometestvalue",
			want:      userauthz.Decision("Extra values does not contain \"sometestvalue\""),
		},
		"double": {
			haveKey:   mockExtraKey,
			haveValue: "testtest",
			want:      userauthz.Decision("Extra values does not contain \"testtest\""),
		},
		"empty": {
			haveKey:   mockExtraKey,
			haveValue: "",
			want:      userauthz.Decision("Extra values does not contain \"\""),
		},
		"missing_key": {
			haveKey:   "example.com/test",
			haveValue: "test",
			want:      userauthz.Decision("Extra values does not contain \"test\""),
		},
		"empty_key": {
			haveKey:   "",
			haveValue: "test",
			want:      userauthz.Decision("Extra values does not contain \"test\""),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RequireExtra(test.haveKey, test.haveValue)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireExtra(%q, %q) authorization returned %q; expected %q", test.haveKey, test.haveValue, got, test.want)
			}
		})
	}
}

func TestRejectExtra(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		haveKey   string
		haveValue string
		want      userauthz.Decision
	}{
		"equal": {
			haveKey:   mockExtraKey,
			haveValue: "test",
			want:      userauthz.Decision("Extra values contains \"test\""),
		},
		"fold": {
			haveKey:   mockExtraKey,
			haveValue: "TEST",
			want:      userauthz.DecisionAllow,
		},
		"substring": {
			haveKey:   mockExtraKey,
			haveValue: "sometestvalue",
			want:      userauthz.DecisionAllow,
		},
		"double": {
			haveKey:   mockExtraKey,
			haveValue: "testtest",
			want:      userauthz.DecisionAllow,
		},
		"empty": {
			haveKey:   mockExtraKey,
			haveValue: "",
			want:      userauthz.DecisionAllow,
		},
		"missing_key": {
			haveKey:   "example.com/test",
			haveValue: "test",
			want:      userauthz.DecisionAllow,
		},
		"empty_key": {
			haveKey:   "",
			haveValue: "test",
			want:      userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RejectExtra(test.haveKey, test.haveValue)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectExtra(%q, %q) authorization returned %q; expected %q", test.haveKey, test.haveValue, got, test.want)
			}
		})
	}
}
