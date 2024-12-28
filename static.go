package userauthz

var (
	// AlwaysAllowAuthorizer is an [Authorizer] implementation which
	// returns [DecisionAllow] unconditionally
	AlwaysAllowAuthorizer = AuthorizerDecision(DecisionAllow)
	// AlwaysAllowAuthorizer is an [Authorizer] implementation which
	// returns [DecisionNoOpinion] unconditionally
	AlwaysNoOpinionAuthorizer = AuthorizerDecision(DecisionNoOpinion)
	// AlwaysAllowAuthorizer is an [Authorizer] implementation which
	// rejects any authorization request
	AlwaysDenyAuthorizer = AuthorizerDecision(Decision("Everything is forbidden."))
)
