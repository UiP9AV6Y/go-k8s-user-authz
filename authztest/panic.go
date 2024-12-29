package authztest

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

// AlwaysPanicAuthorizer returns an [userauthz.Authorizer] which
// always panics. It is intended for test cases where an [userauthz.Authorizer]
// is required to satisfy the interface contract, but is never intended to be
// actually used.
func AlwaysPanicAuthorizer() userauthz.Authorizer {
	result := func(_ context.Context, _ user.Info) userauthz.Decision {
		panic("userauthz.Authorizer logic should not have been called")

		return userauthz.DecisionNoOpinion
	}

	return userauthz.AuthorizerFunc(result)
}
