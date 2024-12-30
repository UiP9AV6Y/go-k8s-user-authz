package userinfo

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RequireAnyUIDs returns an [userauthz.Authorizer] inspecting
// the [user.Info] identifier information. Access is denied
// unless the UID matches at least one of the given items.
// An empty filter returns an [userauthz.Authorizer] rejecting everything.
func RequireAnyUIDs(n []string) userauthz.Authorizer {
	deny := userauthz.Decision("User is not in the allow list")
	if len(n) == 0 {
		return userauthz.AuthorizerDecision(deny)
	}

	return authorizeUIDs(n, true, deny)
}

// RejectAnyUIDs returns an [userauthz.Authorizer] inspecting
// the [user.Info] identifier information. Access is denied
// if the UID matches any of the given items.
// An empty filter returns [userauthz.AlwaysAllowAuthorizer].
func RejectAnyUIDs(n []string) userauthz.Authorizer {
	deny := userauthz.Decision("User is on the deny list")
	if len(n) == 0 {
		return userauthz.AlwaysAllowAuthorizer
	}

	return authorizeUIDs(n, false, deny)
}

func authorizeUIDs(n []string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	result := func(_ context.Context, u user.Info) userauthz.Decision {
		ok := slices.Contains(n, u.GetUID())
		if ok == want {
			return userauthz.DecisionAllow
		}

		return deny
	}

	return userauthz.AuthorizerFunc(result)
}
