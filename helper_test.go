package userauthz_test

import (
	"k8s.io/api/authentication/v1"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
)

const mockExtraKey = "test.golang.org/token-scopes"

func mockUserInfo() user.Info {
	groups := []string{"spec", "test", "mocks"}
	extra := map[string]v1.ExtraValue{
		mockExtraKey: v1.ExtraValue(groups),
	}
	info := v1.UserInfo{
		Username: "mock",
		UID:      "1234567890",
		Groups:   groups,
		Extra:    extra,
	}

	return userauthz.NewV1UserInfo(info)
}
