package userinfo

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// RejectExtra returns an [userauthz.Authorizer] inspecting
// the [user.Info] extra values. Access is denied
// unless the given key exists with the matching value.
// An absence of the key is treated as mismatch,
// resulting in rejection.
func RequireExtra(k, v string) userauthz.Authorizer {
	deny := userauthz.Decisionf("Extra values does not contain %q", v)

	return authorizeExtra(k, v, true, deny)
}

// RejectExtra returns an [userauthz.Authorizer] inspecting
// the [user.Info] extra values. Access is denied
// if the given key exists with the matching value.
// An absence of the key is treated as mismatch,
// resulting in [userauthz.DecisionAllow].
func RejectExtra(k, v string) userauthz.Authorizer {
	deny := userauthz.Decisionf("Extra values contains %q", v)

	return authorizeExtra(k, v, false, deny)
}

func authorizeExtra(k, v string, want bool, deny userauthz.Decision) userauthz.Authorizer {
	var mismatch userauthz.Decision
	if want {
		mismatch = deny
	} else {
		mismatch = userauthz.DecisionAllow
	}

	result := func(_ context.Context, u user.Info) userauthz.Decision {
		extra := u.GetExtra()
		if extra == nil {
			return mismatch
		}

		vs, ok := extra[k]
		if !ok {
			return mismatch
		}

		ok = slices.Contains(vs, v)
		if ok == want {
			return userauthz.DecisionAllow
		}

		return deny
	}

	return userauthz.AuthorizerFunc(result)
}
