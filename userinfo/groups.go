package userinfo

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RequireAnyGroups returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// unless the group memberships match at least one of the given items.
// An empty filter returns an [userauthz.Authorizer] rejecting everything.
func RequireAnyGroups(g []string) userauthz.Authorizer {
	deny := userauthz.Decision("Insufficient group memberships")
	if len(g) == 0 {
		return userauthz.AuthorizerDecision(deny)
	}

	return authorizeAnyGroups(g, true, deny)
}

// RequireAllGroups returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// unless the group memberships match every one of the given items.
// An empty filter returns [userauthz.AlwaysAllowAuthorizer].
func RequireAllGroups(g []string) userauthz.Authorizer {
	deny := userauthz.Decision("Insufficient group memberships")
	if len(g) == 0 {
		return userauthz.AlwaysAllowAuthorizer
	}

	return authorizeAllGroups(g, true, deny)
}

// RejectAnyGroups returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// if the group memberships match any of the given items.
// An empty filter returns [userauthz.AlwaysAllowAuthorizer].
func RejectAnyGroups(g []string) userauthz.Authorizer {
	deny := userauthz.Decision("Group membership resulted in rejection")
	if len(g) == 0 {
		return userauthz.AlwaysAllowAuthorizer
	}

	return authorizeAnyGroups(g, false, deny)
}

// RejectAllGroups returns an [userauthz.Authorizer] inspecting
// the [user.Info] group information. Access is denied
// if the group memberships match every one of the given items.
// An empty filter returns an [userauthz.Authorizer] rejecting everything.
func RejectAllGroups(g []string) userauthz.Authorizer {
	deny := userauthz.Decision("Group membership resulted in rejection")
	if len(g) == 0 {
		return userauthz.AuthorizerDecision(deny)
	}

	return authorizeAllGroups(g, false, deny)
}

func authorizeAnyGroups(g []string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	var mismatch userauthz.Decision
	var found userauthz.Decision
	if want {
		mismatch = deny
		found = userauthz.DecisionAllow
	} else {
		mismatch = userauthz.DecisionAllow
		found = deny
	}

	result := func(_ context.Context, u user.Info) userauthz.Decision {
		groups := u.GetGroups()
		if groups == nil {
			return mismatch
		}

		for _, i := range u.GetGroups() {
			ok := slices.Contains(g, i)
			if ok {
				return found
			}
		}

		return mismatch
	}

	return userauthz.AuthorizerFunc(result)
}

func authorizeAllGroups(g []string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	var mismatch userauthz.Decision
	var found userauthz.Decision
	if want {
		mismatch = deny
		found = userauthz.DecisionAllow
	} else {
		mismatch = userauthz.DecisionAllow
		found = deny
	}

	result := func(_ context.Context, u user.Info) userauthz.Decision {
		var matches int
		groups := u.GetGroups()
		if groups == nil {
			return mismatch
		}

		for _, i := range u.GetGroups() {
			ok := slices.Contains(g, i)
			if ok {
				matches += 1
			}
		}

		if matches == len(g) {
			return found
		} else {
			return mismatch
		}
	}

	return userauthz.AuthorizerFunc(result)
}
