package pkix

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// NewCACertificate creates a new CA Certificate
// Key: pem encoded RSA PRIVATE KEY
func NewCACertificate(key []byte) ([]byte, error) {
	blk, _ := pem.Decode(key)
	if blk.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("invalid PEM block: " + blk.Type)
	}
	pk, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}

	tpl := x509.Certificate{
		SerialNumber:                big.NewInt(1),
		Subject:                     pkix.Name{},
		NotBefore:                   time.Now().Add(time.Minute * -15),
		NotAfter:                    time.Now().AddDate(20, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		SubjectKeyId:                nil,
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	subjectKeyID, err := GenSubjectKeyID(pk.PublicKey)
	if err != nil {
		return nil, err
	}

	tpl.SubjectKeyId = subjectKeyID

	//TODO: get stuff below dynamically
	tpl.Subject.Country = []string{"BR"}
	tpl.Subject.Province = []string{"Sao Paulo"}
	tpl.Subject.Locality = []string{"Sao Paulo"}
	tpl.Subject.Organization = []string{"ztls Self Signed Certificates"}
	tpl.Subject.OrganizationalUnit = []string{"IT"}
	tpl.Subject.CommonName = "ztls"

	crtbytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &pk.PublicKey, pk)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   crtbytes,
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type keyForASN1 struct {
	N *big.Int
	E int
}

func GenSubjectKeyID(key rsa.PublicKey) ([]byte, error) {
	raw, err := asn1.Marshal(keyForASN1{
		N: key.N,
		E: key.E,
	})
	if err != nil {
		return nil, err
	}
	hash := sha1.Sum(raw)
	return hash[:], nil
}
