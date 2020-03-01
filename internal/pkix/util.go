package pkix

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
)

type PEMLabel string

const (
	PEMCertificate        PEMLabel = "CERTIFICATE"
	PEMRSAPrivateKey      PEMLabel = "RSA PRIVATE KEY"
	PEMCertificateRequest PEMLabel = "CERTIFICATE REQUEST"
)

func DecodePEM(rawpem []byte, label PEMLabel, password []byte) ([]byte, error) {
	block, _ := pem.Decode(rawpem)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM bytes (pem.Decode)")
	}
	if block.Type != string(label) {
		return nil, fmt.Errorf("invalid PEM label (expected %v, but got %v)", label, block.Type)
	}
	blkbytes := block.Bytes
	if len(password) > 0 {
		var err error
		blkbytes, err = x509.DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}
	}
	return blkbytes, nil
}

func UnencryptedRSAPrivateKeyPEM(rawpem []byte, password []byte) ([]byte, error) {
	if rawpem != nil && password == nil {
		return rawpem, nil
	}
	der, err := DecodePEM(rawpem, PEMRSAPrivateKey, password)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  string(PEMRSAPrivateKey),
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func parseIPs(ips []string) ([]net.IP, error) {
	if len(ips) == 1 && ips[0] == "" {
		return []net.IP{}, nil
	}
	outp := make([]net.IP, len(ips))
	for i, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return nil, fmt.Errorf("Invalid IP address: %s", ip)
		}
		outp[i] = parsedIP
	}
	return outp, nil
}
