package userauthz

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"
)

// RejectGroup returns an [Authorizer] inspecting
// the [user.Info] group information. Access is denied
// unless the group is found.
func RequireGroup(g string) Authorizer {
	deny := Decisionf("Require membership of %q", g)

	return authorizeGroup(g, true, deny)
}

// RejectGroup returns an [Authorizer] inspecting
// the [user.Info] group information. Access is denied
// if the given value is found in the group list.
func RejectGroup(g string) Authorizer {
	deny := Decisionf("Members of %q are not allowed", g)

	return authorizeGroup(g, false, deny)
}

func authorizeGroup(g string, want bool, deny Decision) Authorizer {
	var mismatch Decision
	if want {
		mismatch = deny
	} else {
		mismatch = DecisionAllow
	}

	result := func(_ context.Context, u user.Info) Decision {
		groups := u.GetGroups()
		if groups == nil {
			return mismatch
		}

		ok := slices.Contains(groups, g)
		if ok == want {
			return DecisionAllow
		}

		return deny
	}

	return AuthorizerFunc(result)
}
