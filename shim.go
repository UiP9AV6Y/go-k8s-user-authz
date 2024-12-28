package userauthz

import (
	"k8s.io/api/authentication/v1"
	"k8s.io/api/authentication/v1beta1"

	"k8s.io/apiserver/pkg/authentication/user"
)

type v1UserInfo struct {
	v1.UserInfo

	extraValues map[string][]string
}

func (i *v1UserInfo) GetName() string               { return i.UserInfo.Username }
func (i *v1UserInfo) GetUID() string                { return i.UserInfo.UID }
func (i *v1UserInfo) GetGroups() []string           { return i.UserInfo.Groups }
func (i *v1UserInfo) GetExtra() map[string][]string { return i.extraValues }

// NewV1UserInfo returns a [user.Info] proxy
// for [v1.UserInfo] objects.
func NewV1UserInfo(i v1.UserInfo) user.Info {
	extraValues := make(map[string][]string, len(i.Extra))
	for i, v := range i.Extra {
		extraValues[i] = []string(v)
	}

	return &v1UserInfo{
		UserInfo:    i,
		extraValues: extraValues,
	}
}

type v1beta1UserInfo struct {
	v1beta1.UserInfo

	extraValues map[string][]string
}

func (i *v1beta1UserInfo) GetName() string               { return i.UserInfo.Username }
func (i *v1beta1UserInfo) GetUID() string                { return i.UserInfo.UID }
func (i *v1beta1UserInfo) GetGroups() []string           { return i.UserInfo.Groups }
func (i *v1beta1UserInfo) GetExtra() map[string][]string { return i.extraValues }

// NewV1UserInfo returns a [user.Info] proxy
// for [v1beta1.UserInfo] objects.
func NewV1Beta1UserInfo(i v1beta1.UserInfo) user.Info {
	extraValues := make(map[string][]string, len(i.Extra))
	for i, v := range i.Extra {
		extraValues[i] = []string(v)
	}

	return &v1beta1UserInfo{
		UserInfo:    i,
		extraValues: extraValues,
	}
}
