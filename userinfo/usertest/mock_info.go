package usertest

import (
	"hash/maphash"
	"strconv"

	_ "k8s.io/apiserver/pkg/authentication/user"
)

// MockExtraKey is the key used for the [MockUser] extra values.
const MockExtraKey = "github.com/UiP9AV6Y/go-k8s-user-authz"

var mockSeed = maphash.MakeSeed()

// MockUser implements [user.Info] and is inteded for testing
// purposes. Its value is the user name.
type MockUser string

// GetName returns u.
func (u MockUser) GetName() string { return string(u) }

// GetUID returns a hash of u. It uses [maphash.String]
// to generate a numeric value, which is then converted
// to a string using [strconv.FormatUint].
func (u MockUser) GetUID() string {
	csum := maphash.String(mockSeed, string(u))

	return strconv.FormatUint(csum, 10)
}

// GetGroups returns an array with a single item: u
func (u MockUser) GetGroups() []string {
	return []string{string(u)}
}

// GetExtra returns a map with a single key: [MockExtraKey].
// The value of that map entry is [MockUser.GetGroups].
func (u MockUser) GetExtra() map[string][]string {
	return map[string][]string{MockExtraKey: u.GetGroups()}
}
