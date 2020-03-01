package pkix

import (
	"bytes"
	"encoding/pem"
	"crypto/x509"
	"crypto/rand"
	"crypto/rsa"
)

// NewKey creates a new RSA Private Key (PEM encoded)
func NewKey(size int) ([]byte, error) {
	privk, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	pemblk := &pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privk),
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemblk); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}