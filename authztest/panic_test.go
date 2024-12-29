package authztest_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz/authztest"
)

func TestAlwaysPanicAuthorizer(t *testing.T) {
	subject := authztest.AlwaysPanicAuthorizer()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Authorizer did not panic")
		}
	}()

	// hmm, nil might cause a panic leading to a false-positive
	subject.Authorize(context.Background(), nil)
}
