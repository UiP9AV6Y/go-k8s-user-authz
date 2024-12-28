package userauthz

import (
	"context"
	"strings"

	"k8s.io/apiserver/pkg/authentication/user"
)

// InvertDecision returns an [Authorizer] instance which
// inverts the decision of the given instance. The given
// denial is returned if the underlying [Authorizer] yields
// [DecisionAllow]. A result of [DecisionNoOpinion] remains
// unchanged.
func InvertDecision(a Authorizer, deny Decision) Authorizer {
	result := func(ctx context.Context, u user.Info) Decision {
		reason := a.Authorize(ctx, u)
		if reason == DecisionAllow {
			return deny
		} else if reason == DecisionNoOpinion {
			return DecisionNoOpinion
		}

		return DecisionAllow
	}

	return AuthorizerFunc(result)
}

// AllowNoOpinion returns an [Authorizer] instance which
// turns any [DecisionNoOpinion] result into [DecisionAllow].
func AllowNoOpinion(a Authorizer) Authorizer {
	result := func(ctx context.Context, u user.Info) (reason Decision) {
		reason = a.Authorize(ctx, u)
		if reason == DecisionNoOpinion {
			reason = DecisionAllow
		}

		return
	}

	return AuthorizerFunc(result)
}

// RejectNoOpinion returns an [Authorizer] instance which
// turns any [DecisionNoOpinion] result into the provided
// denial reason.
func RejectNoOpinion(a Authorizer, deny Decision) Authorizer {
	result := func(ctx context.Context, u user.Info) (reason Decision) {
		reason = a.Authorize(ctx, u)
		if reason == DecisionNoOpinion {
			reason = deny
		}

		return
	}

	return AuthorizerFunc(result)
}

// RequireAny requires any of the given authorizer
// instances to yield [DecisionAllow] in order to
// return the same. A single result of [DecisionNoOpinion]
// will cause the whole [Authorizer] to return the same
// value. Anything else will return the concatenated
// denial reasons. An empty input list will return [DecisionNoOpinion].
func RequireAny(a []Authorizer) Authorizer {
	result := func(ctx context.Context, u user.Info) Decision {
		deny := make([]string, 0, len(a))
		noop := len(a) == 0
		for _, i := range a {
			reason := i.Authorize(ctx, u)
			if reason == DecisionAllow {
				return DecisionAllow
			} else if reason == DecisionNoOpinion {
				noop = true
			} else {
				deny = append(deny, string(reason))
			}
		}

		if noop {
			return DecisionNoOpinion
		}

		return Decision(strings.Join(deny, "; "))
	}

	return AuthorizerFunc(result)
}

// RequireAll requires all given [Authorizer] instances
// to yield [DecisionAllow], otherwiese the first violation
// is returned. An empty input list returns [DecisionAllow].
func RequireAll(a []Authorizer) Authorizer {
	result := func(ctx context.Context, u user.Info) Decision {
		for _, i := range a {
			reason := i.Authorize(ctx, u)
			if reason != DecisionAllow {
				return reason
			}
		}

		return DecisionAllow
	}

	return AuthorizerFunc(result)
}
