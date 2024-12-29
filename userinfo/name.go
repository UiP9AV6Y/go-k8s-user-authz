package userinfo

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RejectName returns an [userauthz.Authorizer] inspecting
// the [user.Info] username information. Access is denied
// unless the username matches.
func RequireName(n string) userauthz.Authorizer {
	deny := userauthz.Decisionf("User %q is required", n)

	return authorizeName(n, true, deny)
}

// RejectName returns an [userauthz.Authorizer] inspecting
// the [user.Info] username information. Access is denied
// if the username matches.
func RejectName(n string) userauthz.Authorizer {
	deny := userauthz.Decisionf("User %q is not allowed", n)

	return authorizeName(n, false, deny)
}

func authorizeName(n string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	result := func(_ context.Context, u user.Info) userauthz.Decision {
		ok := n == u.GetName()
		if ok == want {
			return userauthz.DecisionAllow
		}

		return deny
	}

	return userauthz.AuthorizerFunc(result)
}
