package accounts

import (
	"os/user"
)

const (
	DevadminGidString = "5000"
	DevreadGidString  = "5001"
)

type userLookupFunc func(username string) (*user.User, error)

func userInDevadminDevreadGid(username string, lookup userLookupFunc) (bool, error) {
	u, err := lookup(username)
	if err != nil {
		return false, err
	}
	return u.Gid == DevadminGidString || u.Gid == DevreadGidString, nil
}

func UserInDevadminDevreadGid(username string) (bool, error) {
	return userInDevadminDevreadGid(username, user.Lookup)
}
