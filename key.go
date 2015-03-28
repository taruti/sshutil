package sshutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// KeyLoader provides an interface to load or create private keys.
type KeyLoader struct {
	Path  string
	Flags uint32
}

const (
	// Create the key if needed
	Create = 1 << iota
	// Save created keys to disk
	Save
)

// Load a private key with the given parameters.
func (kl KeyLoader) Load() (ssh.Signer, error) {
	var bs []byte
	var e error
	if kl.Path != "" {
		bs, e = ioutil.ReadFile(kl.Path)
	}
	if bs == nil {
		if kl.Flags&Create == 0 {
			if e == nil {
				e = errors.New("SSH host key creation not enabled")
			}
			return nil, e
		}
		bs, e = createKeyPEM()
		if e != nil {
			return nil, e
		}
		if kl.Flags&Save != 0 {
			// errors from the write are ignored here.
			_ = ioutil.WriteFile(kl.Path, bs, 0400)
		}
	}
	return ssh.ParsePrivateKey(bs)
}

func createKeyPEM() ([]byte, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	b, e := x509.MarshalECPrivateKey(k)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}
