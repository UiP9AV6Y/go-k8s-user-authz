package userinfo

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RequireAnyNames returns an [userauthz.Authorizer] inspecting
// the [user.Info] username information. Access is denied
// unless the username matches at least one of the given items.
// An empty filter returns an [userauthz.Authorizer] rejecting everything.
func RequireAnyNames(n []string) userauthz.Authorizer {
	deny := userauthz.Decision("User is not in the allow list")
	if len(n) == 0 {
		return userauthz.AuthorizerDecision(deny)
	}

	return authorizeNames(n, true, deny)
}

// RejectAnyNames returns an [userauthz.Authorizer] inspecting
// the [user.Info] username information. Access is denied
// if the username matches any of the given items.
// An empty filter returns [userauthz.AlwaysAllowAuthorizer].
func RejectAnyNames(n []string) userauthz.Authorizer {
	deny := userauthz.Decision("User is on the deny list")
	if len(n) == 0 {
		return userauthz.AlwaysAllowAuthorizer
	}

	return authorizeNames(n, false, deny)
}

func authorizeNames(n []string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	result := func(_ context.Context, u user.Info) userauthz.Decision {
		ok := slices.Contains(n, u.GetName())
		if ok == want {
			return userauthz.DecisionAllow
		}

		return deny
	}

	return userauthz.AuthorizerFunc(result)
}
