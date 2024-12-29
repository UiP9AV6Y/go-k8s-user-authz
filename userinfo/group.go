package userinfo

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RejectGroup returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// unless the group is found.
func RequireGroup(g string) userauthz.Authorizer {
	deny := userauthz.Decisionf("Require membership of %q", g)

	return authorizeGroup(g, true, deny)
}

// RejectGroup returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// if the given value is found in the group list.
func RejectGroup(g string) userauthz.Authorizer {
	deny := userauthz.Decisionf("Members of %q are not allowed", g)

	return authorizeGroup(g, false, deny)
}

func authorizeGroup(g string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	var mismatch userauthz.Decision
	if want {
		mismatch = deny
	} else {
		mismatch = userauthz.DecisionAllow
	}

	result := func(_ context.Context, u user.Info) userauthz.Decision {
		groups := u.GetGroups()
		if groups == nil {
			return mismatch
		}

		ok := slices.Contains(groups, g)
		if ok == want {
			return userauthz.DecisionAllow
		}

		return deny
	}

	return userauthz.AuthorizerFunc(result)
}
