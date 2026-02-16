package accounts

import (
	"errors"
	"os/user"
	"testing"
)

func mockLookup(gid string) userLookupFunc {
	return func(username string) (*user.User, error) {
		return &user.User{Username: username, Gid: gid}, nil
	}
}

func TestUserInDevadminDevreadGid(t *testing.T) {
	cases := []struct {
		name    string
		lookup  userLookupFunc
		want    bool
		wantErr bool
	}{
		{
			name:   "devadmin gid",
			lookup: mockLookup(DevadminGidString),
			want:   true,
		},
		{
			name:   "devread gid",
			lookup: mockLookup(DevreadGidString),
			want:   true,
		},
		{
			name:   "other gid",
			lookup: mockLookup("1000"),
			want:   false,
		},
		{
			name:    "lookup error",
			lookup:  func(username string) (*user.User, error) { return nil, errors.New("not found") },
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := userInDevadminDevreadGid("testuser", c.lookup)
			if (err != nil) != c.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, c.wantErr)
			}
			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
