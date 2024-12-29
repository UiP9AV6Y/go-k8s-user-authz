package userauthz_test

import (
	"k8s.io/apiserver/pkg/authentication/user"
)

type mockUser string

func (u mockUser) GetName() string               { return string(u) }
func (u mockUser) GetUID() string                { return string(u) }
func (_ mockUser) GetGroups() []string           { return []string{} }
func (_ mockUser) GetExtra() map[string][]string { return map[string][]string{} }

func mockUserInfo() user.Info {
	return mockUser("mock")
}
