package usertest

import (
	"hash/crc64"
	"strconv"

	_ "k8s.io/apiserver/pkg/authentication/user"
)

// MockExtraKey is the key used for the [MockUser] extra values.
const MockExtraKey = "github.com/UiP9AV6Y/go-k8s-user-authz"
const DefaultUserName = "mock"

var mockTable = crc64.MakeTable(crc64.ISO)

// MockUser implements [user.Info] and is inteded for testing
// purposes. Its value is the user name.
type MockUser []string

// NewMockUser returns a [MockUser] instance
// with the given name.
func NewMockUser(name string) MockUser {
	return MockUser([]string{name})
}

// GetName returns the first item of u,
// or [DefaultUserName] if its length is zero.
func (u MockUser) GetName() string {
	if len(u) == 0 {
		return DefaultUserName
	}

	return u[0]
}

// GetUID returns a hash of u. It uses [crc64.Checksum]
// to generate a numeric value of the [MockUser.GetName],
// which is then converted to a string using [strconv.FormatUint].
func (u MockUser) GetUID() string {
	csum := crc64.Checksum([]byte(u.GetName()), mockTable)

	return strconv.FormatUint(csum, 10)
}

// GetGroups returns an array with a single item: u
func (u MockUser) GetGroups() []string {
	return []string(u)
}

// GetExtra returns a map with a single key: [MockExtraKey].
// The value of that map entry is [MockUser.GetGroups].
func (u MockUser) GetExtra() map[string][]string {
	return map[string][]string{MockExtraKey: u.GetGroups()}
}
