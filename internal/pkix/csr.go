package pkix

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type CSRInfo struct {
	Country            []string
	Province           []string
	Locality           []string
	Organization       []string
	OrganizationalUnit []string
	CommonName         string
	StreetAddress      []string
	PostalCode         []string
	IPs                []string
	Domains            []string
}

func NewCSRPEM(info CSRInfo, keypem, password []byte) ([]byte, error) {
	keybytes, err := DecodePEM(keypem, PEMRSAPrivateKey, password)
	if err != nil {
		return nil, err
	}
	pk, err := x509.ParsePKCS1PrivateKey(keybytes)
	if err != nil {
		return nil, err
	}

	csrPkixName := pkix.Name{
		Country:            info.Country,
		Province:           info.Province,
		Locality:           info.Locality,
		Organization:       info.Organization,
		OrganizationalUnit: info.OrganizationalUnit,
		CommonName:         info.CommonName,
		StreetAddress:      info.StreetAddress,
		PostalCode:         info.PostalCode,
	}

	iplist, err := parseIPs(info.IPs)
	if err != nil {
		return nil, err
	}

	tpl := x509.CertificateRequest{
		Subject:     csrPkixName,
		IPAddresses: iplist,
		DNSNames:    info.Domains,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &tpl, pk)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   csrBytes,
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type NewCertificatePEMInput struct {
	CACert       *x509.Certificate
	CAKey        *rsa.PrivateKey
	CSR          *x509.CertificateRequest
	SerialNumber int64
	Expires      time.Time
}

func NewCertificatePEM(input NewCertificatePEMInput) ([]byte, error) {

	tpl := x509.Certificate{
		SerialNumber: big.NewInt(input.SerialNumber),
		Subject:      pkix.Name{},
		NotBefore:    time.Now().Add(time.Minute * -15),
		NotAfter:     time.Now().AddDate(1, 0, 1),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		//UnknownExtKeyUsage: nil,
		// activate CA
		BasicConstraintsValid: false,
		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		SubjectKeyId: nil,
		// Subject Alternative Name
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	if input.SerialNumber == 0 {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, err
		}
		tpl.SerialNumber = serialNumber
	}

	// pkix.Name{} doesn't take ordering into account.
	// RawSubject works because CreateCertificate() first checks if
	// RawSubject has a value.
	tpl.RawSubject = input.CSR.RawSubject

	csrpubk := input.CSR.PublicKey.(*rsa.PublicKey)
	var err error
	tpl.SubjectKeyId, err = GenSubjectKeyID(*csrpubk)
	if err != nil {
		return nil, err
	}
	if !input.Expires.IsZero() && input.Expires.Before(input.CACert.NotAfter) {
		tpl.NotAfter = input.Expires
	} else {
		tpl.NotAfter = input.CACert.NotAfter
	}

	tpl.IPAddresses = input.CSR.IPAddresses
	tpl.DNSNames = input.CSR.DNSNames

	raw, err := x509.CreateCertificate(rand.Reader, &tpl, input.CACert, input.CSR.PublicKey, input.CAKey)

	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   raw,
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, pemBlock); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
