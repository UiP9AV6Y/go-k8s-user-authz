package userauthz

import (
	"context"
	"slices"

	"k8s.io/apiserver/pkg/authentication/user"
)

// RejectExtra returns an [Authorizer] inspecting
// the [user.Info] extra values. Access is denied
// unless the given key exists with the matching value.
// An absence of the key is treated as mismatch,
// resulting in rejection.
func RequireExtra(k, v string) Authorizer {
	deny := Decisionf("Extra values does not contain %q", v)

	return authorizeExtra(k, v, true, deny)
}

// RejectExtra returns an [Authorizer] inspecting
// the [user.Info] extra values. Access is denied
// if the given key exists with the matching value.
// An absence of the key is treated as mismatch,
// resulting in [DecisionAllow].
func RejectExtra(k, v string) Authorizer {
	deny := Decisionf("Extra values contains %q", v)

	return authorizeExtra(k, v, false, deny)
}

func authorizeExtra(k, v string, want bool, deny Decision) Authorizer {
	var mismatch Decision
	if want {
		mismatch = deny
	} else {
		mismatch = DecisionAllow
	}

	result := func(_ context.Context, u user.Info) Decision {
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
			return DecisionAllow
		}

		return deny
	}

	return AuthorizerFunc(result)
}
