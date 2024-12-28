package userauthz_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

func TestInvertDecision(t *testing.T) {
	double := mockUserInfo()
	denied := userauthz.Decision("test authorization denied")
	tests := map[string]struct {
		haveAuthorizer userauthz.Authorizer
		haveDeny       userauthz.Decision
		want           userauthz.Decision
	}{
		"allow": {
			haveAuthorizer: userauthz.AlwaysAllowAuthorizer,
			haveDeny:       denied,
			want:           denied,
		},
		"deny": {
			haveAuthorizer: userauthz.AlwaysDenyAuthorizer,
			haveDeny:       denied,
			want:           userauthz.DecisionAllow,
		},
		"no_opinion": {
			haveAuthorizer: userauthz.AlwaysNoOpinionAuthorizer,
			haveDeny:       denied,
			want:           userauthz.DecisionNoOpinion,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.InvertDecision(test.haveAuthorizer, test.haveDeny)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("InvertDecision(%q, %q) authorization returned %q; expected %q", test.haveAuthorizer, test.haveDeny, got, test.want)
			}
		})
	}
}

func TestRejectNoOpinion(t *testing.T) {
	double := mockUserInfo()
	denied := userauthz.Decision("test authorization denied")
	tests := map[string]struct {
		haveAuthorizer userauthz.Authorizer
		haveDeny       userauthz.Decision
		want           userauthz.Decision
	}{
		"allow": {
			haveAuthorizer: userauthz.AlwaysAllowAuthorizer,
			haveDeny:       denied,
			want:           userauthz.DecisionAllow,
		},
		"deny": {
			haveAuthorizer: userauthz.AlwaysDenyAuthorizer,
			haveDeny:       denied,
			want:           userauthz.Decision("Everything is forbidden."),
		},
		"no_opinion": {
			haveAuthorizer: userauthz.AlwaysNoOpinionAuthorizer,
			haveDeny:       denied,
			want:           denied,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.RejectNoOpinion(test.haveAuthorizer, test.haveDeny)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectNoOpinion(%q, %q) authorization returned %q; expected %q", test.haveAuthorizer, test.haveDeny, got, test.want)
			}
		})
	}
}

func TestAllowNoOpinion(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		haveAuthorizer userauthz.Authorizer
		want           userauthz.Decision
	}{
		"allow": {
			haveAuthorizer: userauthz.AlwaysAllowAuthorizer,
			want:           userauthz.DecisionAllow,
		},
		"deny": {
			haveAuthorizer: userauthz.AlwaysDenyAuthorizer,
			want:           userauthz.Decision("Everything is forbidden."),
		},
		"no_opinion": {
			haveAuthorizer: userauthz.AlwaysNoOpinionAuthorizer,
			want:           userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.AllowNoOpinion(test.haveAuthorizer)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("AllowNoOpinion(%q) authorization returned %q; expected %q", test.haveAuthorizer, got, test.want)
			}
		})
	}
}

func TestRequireAny(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		haveAuthorizer []userauthz.Authorizer
		want           userauthz.Decision
	}{
		"allow_all": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysAllowAuthorizer,
			},
			want: userauthz.DecisionAllow,
		},
		"allow_deny": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AuthorizerDecision(userauthz.Decision("reject 1")),
				userauthz.AlwaysAllowAuthorizer,
			},
			want: userauthz.DecisionAllow,
		},
		"allow_undecisive": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysNoOpinionAuthorizer,
				userauthz.AlwaysAllowAuthorizer,
			},
			want: userauthz.DecisionAllow,
		},
		"deny": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AuthorizerDecision(userauthz.Decision("reject 1")),
				userauthz.AuthorizerDecision(userauthz.Decision("reject 2")),
			},
			want: userauthz.Decision("reject 1; reject 2"),
		},
		"no_opinion_empty": {
			haveAuthorizer: []userauthz.Authorizer{},
			want:           userauthz.DecisionNoOpinion,
		},
		"no_opinion_undecisive": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysNoOpinionAuthorizer,
			},
			want: userauthz.DecisionNoOpinion,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.RequireAny(test.haveAuthorizer)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAny([]Authorizer) authorization returned %q; expected %q", got, test.want)
			}
		})
	}
}

func TestRequireAll(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		haveAuthorizer []userauthz.Authorizer
		want           userauthz.Decision
	}{
		"allow": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysAllowAuthorizer,
			},
			want: userauthz.DecisionAllow,
		},
		"allow_empty": {
			haveAuthorizer: []userauthz.Authorizer{},
			want:           userauthz.DecisionAllow,
		},
		"deny": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysDenyAuthorizer,
				userauthz.AlwaysDenyAuthorizer,
			},
			want: userauthz.Decision("Everything is forbidden."),
		},
		"no_opinion": {
			haveAuthorizer: []userauthz.Authorizer{
				userauthz.AlwaysNoOpinionAuthorizer,
				userauthz.AlwaysAllowAuthorizer,
				userauthz.AlwaysDenyAuthorizer,
			},
			want: userauthz.DecisionNoOpinion,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userauthz.RequireAll(test.haveAuthorizer)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAll([]Authorizer) authorization returned %q; expected %q", got, test.want)
			}
		})
	}
}
