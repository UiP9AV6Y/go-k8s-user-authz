package userauthz

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authentication/user"
)

// Decision represents an authorization result.
type Decision string

const (
	// DecisionAllow means that an authorizer decided to allow the user.
	DecisionAllow Decision = ""
	// DecisionNoOpinion means that an authorizer has no opinion on whether
	// to allow or deny a user.
	DecisionNoOpinion Decision = "UNKNOWN"
)

var (
	decisionAllowString     = "Authorization succeeded"
	decisionNoOpinionString = "Authorization is inconclusive"
)

func (d Decision) String() string {
	if d == DecisionAllow {
		return decisionAllowString
	} else if d == DecisionNoOpinion {
		return decisionNoOpinionString
	}

	return string(d)
}

// Decisionf is a wrapper around [fmt.Sprintf] using
// the provided parameters to return a [Decision].
func Decisionf(format string, args ...interface{}) Decision {
	return Decision(fmt.Sprintf(format, args...))
}

// Authorizer makes an authorization decision based on information gained by making
// zero or more calls to methods of the [user.Info] interface.
// Any returned error originates from the underlying data source and does not necessarily
// indicate a [DecisionDeny]; Implementation can chose to withold a decision by returning
// [DecisionNoOpinion] as consumers are unlikely to accept a positive response accompanied by an error.
type Authorizer interface {
	Authorize(ctx context.Context, u user.Info) Decision
}

// The AuthorizerFunc type is an adapter to allow the use of ordinary
// functions as authorization evaluators. If f is a function with the appropriate signature,
// AuthorizerFunc(f) is an [Authorizer] that calls f.
type AuthorizerFunc func(ctx context.Context, u user.Info) Decision

// Authorize calls f(ctx, u).
func (f AuthorizerFunc) Authorize(ctx context.Context, u user.Info) Decision {
	return f(ctx, u)
}

// AuthorizerDecision is a precomputed authorization decision. It is suitable
// for testing or as fallback decision when chaining multiple [Authorizer] instances
// together.
type AuthorizerDecision Decision

// String returns the string representation
// of the underlying authorization decision
func (d AuthorizerDecision) String() string {
	return Decision(d).String()
}

// Authorize returns d.
func (d AuthorizerDecision) Authorize(_ context.Context, _ user.Info) Decision {
	return Decision(d)
}
