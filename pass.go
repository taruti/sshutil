package sshutil

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// CreatePasswordCheck creates a simple password checking function suitable for PasswordCallback for testing.
func CreatePasswordCheck(user string, pass []byte) func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	up := &upass{[]byte(user), pass}
	return up.check
}

type upass struct {
	user, pass []byte
}

func (up *upass) check(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	user := []byte(c.User())
	b1 := subtle.ConstantTimeCompare(user, up.user) == 1
	b2 := subtle.ConstantTimeCompare(pass, up.pass) == 1
	if b1 && b2 {
		return nil, nil
	}
	return nil, fmt.Errorf("password rejected for %q", c.User())
}
