package userinfo_test

import (
	"context"
	"testing"

	"github.com/UiP9AV6Y/go-k8s-user-authz"
	"github.com/UiP9AV6Y/go-k8s-user-authz/userinfo"
)

func TestRequireAnyGroups(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal_min": {
			have: []string{"test"},
			want: userauthz.DecisionAllow,
		},
		"equal_one": {
			have: []string{"foo", "test", "gaff"},
			want: userauthz.DecisionAllow,
		},
		"equal_all": {
			have: []string{"spec", "test", "mocks"},
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: []string{"SPEC", "TEST", "MOCKS"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"substring": {
			have: []string{"specmockdouble", "testmockdouble", "mocksmockdouble"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"double": {
			have: []string{"specspec", "testtest", "mocksmocks"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"blank": {
			have: []string{""},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"empty": {
			have: []string{},
			want: userauthz.Decision("Insufficient group memberships"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RequireAnyGroups(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAnyGroups(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRequireAllGroups(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal_min": {
			have: []string{"test"},
			want: userauthz.DecisionAllow,
		},
		"equal_one": {
			have: []string{"foo", "test", "gaff"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"equal_all": {
			have: []string{"spec", "test", "mocks"},
			want: userauthz.DecisionAllow,
		},
		"fold": {
			have: []string{"SPEC", "TEST", "MOCKS"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"substring": {
			have: []string{"specmockdouble", "testmockdouble", "mocksmockdouble"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"double": {
			have: []string{"specspec", "testtest", "mocksmocks"},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"blank": {
			have: []string{""},
			want: userauthz.Decision("Insufficient group memberships"),
		},
		"empty": {
			have: []string{},
			want: userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RequireAllGroups(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RequireAllGroups(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectAnyGroups(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal_min": {
			have: []string{"test"},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
		"equal_one": {
			have: []string{"foo", "test", "gaff"},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
		"equal_all": {
			have: []string{"spec", "test", "mocks"},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
		"fold": {
			have: []string{"SPEC", "TEST", "MOCKS"},
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: []string{"specmockdouble", "testmockdouble", "mocksmockdouble"},
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: []string{"specspec", "testtest", "mocksmocks"},
			want: userauthz.DecisionAllow,
		},
		"blank": {
			have: []string{""},
			want: userauthz.DecisionAllow,
		},
		"empty": {
			have: []string{},
			want: userauthz.DecisionAllow,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RejectAnyGroups(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectAnyGroups(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}

func TestRejectAllGroups(t *testing.T) {
	double := mockUserInfo()
	tests := map[string]struct {
		have []string
		want userauthz.Decision
	}{
		"equal_min": {
			have: []string{"test"},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
		"equal_one": {
			have: []string{"foo", "test", "gaff"},
			want: userauthz.DecisionAllow,
		},
		"equal_all": {
			have: []string{"spec", "test", "mocks"},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
		"fold": {
			have: []string{"SPEC", "TEST", "MOCKS"},
			want: userauthz.DecisionAllow,
		},
		"substring": {
			have: []string{"specmockdouble", "testmockdouble", "mocksmockdouble"},
			want: userauthz.DecisionAllow,
		},
		"double": {
			have: []string{"specspec", "testtest", "mocksmocks"},
			want: userauthz.DecisionAllow,
		},
		"blank": {
			have: []string{""},
			want: userauthz.DecisionAllow,
		},
		"empty": {
			have: []string{},
			want: userauthz.Decision("Group membership resulted in rejection"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			subject := userinfo.RejectAllGroups(test.have)
			got := subject.Authorize(context.Background(), double)

			if got != test.want {
				t.Fatalf("RejectAllGroups(%q) authorization returned %q; expected %q", test.have, got, test.want)
			}
		})
	}
}
