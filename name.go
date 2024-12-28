package userauthz

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"
)

// RejectName returns an [Authorizer] inspecting
// the [user.Info] username information. Access is denied
// unless the username matches.
func RequireName(n string) Authorizer {
	deny := Decisionf("User %q is required", n)

	return authorizeName(n, true, deny)
}

// RejectName returns an [Authorizer] inspecting
// the [user.Info] username information. Access is denied
// if the username matches.
func RejectName(n string) Authorizer {
	deny := Decisionf("User %q is not allowed", n)

	return authorizeName(n, false, deny)
}

func authorizeName(n string, want bool, deny Decision) Authorizer {
	result := func(_ context.Context, u user.Info) Decision {
		ok := n == u.GetName()
		if ok == want {
			return DecisionAllow
		}

		return deny
	}

	return AuthorizerFunc(result)
}
