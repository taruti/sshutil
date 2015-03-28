package sshutil

import (
	"crypto/sha512"
	"encoding/base64"

	"golang.org/x/crypto/ssh"
)

// PublicKeyHash produces a human readable hash of a public key.
func PublicKeyHash(pub ssh.PublicKey) []byte {
	h := sha512.New()
	_, _ = h.Write(pub.Marshal())
	sum := h.Sum(nil)
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(sum)))
	base64.URLEncoding.Encode(dst, sum)
	return dst
}
