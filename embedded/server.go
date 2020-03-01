package embedded

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/gabstv/ztls/internal/pkix"
	echo "github.com/labstack/echo/v4"
	"github.com/rs/zerolog/log"
)

type IDFunc func() int64

var ornd sync.Once
var rn0 *rand.Rand

var RandID IDFunc = func() int64 {
	ornd.Do(func() {
		rn0 = rand.New(rand.NewSource(time.Now().UnixNano()))
	})
	return rn0.Int63()
}

type Server struct {
	ctx    context.Context
	cfg    *Config
	NextID IDFunc

	// http stuff
	httponce    sync.Once
	httphandler *echo.Echo
}

func New(ctx context.Context, cfg *Config) *Server {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Server{ctx: ctx, cfg: cfg, NextID: RandID}
}

func NewWithConfig(ctx context.Context, pemcfg []byte) (*Server, error) {
	cfg, err := UnmarshalConfig(pemcfg)
	if err != nil {
		return nil, err
	}
	return New(ctx, cfg), nil
}

func (s *Server) getkey() *rsa.PrivateKey {
	rawkey, err := pkix.DecodePEM(s.cfg.Rootkey, pkix.PEMRSAPrivateKey, s.cfg.RootkeyPw)
	if err != nil {
		log.Error().Err(err).Msg("getkey() error (PEM)")
		return nil
	}
	rootk, err := x509.ParsePKCS1PrivateKey(rawkey)
	if err != nil {
		log.Error().Err(err).Msg("getkey() error (PARSE)")
		return nil
	}
	return rootk
}

func (s *Server) getca() *x509.Certificate {
	rawcert, err := pkix.DecodePEM(s.cfg.Rootcert, pkix.PEMCertificate, nil)
	if err != nil {
		log.Error().Err(err).Msg("getca() error (PEM)")
		return nil
	}
	rootc, err := x509.ParseCertificate(rawcert)
	if err != nil {
		log.Error().Err(err).Msg("getca() error (PARSE)")
		return nil
	}
	return rootc
}

func (s *Server) NewCertificateRaw(csrpem []byte) (cert []byte, err error) {
	if len(csrpem) < 10 {
		return nil, errInvalidPEM
	}
	csra1, err := pkix.DecodePEM(csrpem, pkix.PEMCertificateRequest, nil)
	if err != nil {
		return nil, err
	}
	creq, err := x509.ParseCertificateRequest(csra1)
	if err != nil {
		return nil, err
	}
	return pkix.NewCertificatePEM(pkix.NewCertificatePEMInput{
		CACert:       s.getca(),
		CAKey:        s.getkey(),
		CSR:          creq,
		SerialNumber: s.NextID(),
		Expires:      time.Now().AddDate(5, 0, 0), //TODO: better expiritaion checks
	})
}

func (s *Server) NewCertificateCSR(csr CSRReader, key []byte) (cert []byte, err error) {
	nfo := pkix.CSRInfo{
		Country:            csr.GetCountry(),
		Province:           csr.GetProvince(),
		Locality:           csr.GetLocality(),
		Organization:       csr.GetOrganization(),
		OrganizationalUnit: csr.GetOrganizationalUnit(),
		StreetAddress:      csr.GetStreetAddress(),
		PostalCode:         csr.GetPostalCode(),
		IPs:                csr.GetIPs(),
		Domains:            csr.GetDomains(),
		CommonName:         csr.GetCommonName(),
	}
	csrpem, err := pkix.NewCSRPEM(nfo, key, nil)
	if err != nil {
		return nil, err
	}
	return s.NewCertificateRaw(csrpem)
}

func (s *Server) NewKey() (key []byte, err error) {
	return pkix.NewKey(4096)
}

func (s *Server) NewClientAuto(serverName string, csr CSRReader) (tlsc *tls.Config, keypem, certpem []byte, err error) {
	keypem, err = s.NewKey()
	if err != nil {
		return
	}
	certpem, err = s.NewCertificateCSR(csr, keypem)
	if err != nil {
		return
	}
	tlscert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		return nil, nil, nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(s.cfg.Rootcert); !ok {
		return nil, nil, nil, errors.New("invalid CA")
	}

	tlsc = &tls.Config{
		ServerName:   serverName,
		Certificates: []tls.Certificate{tlscert},
		RootCAs:      certPool,
	}
	return
}

func (s *Server) NewServerAuto(csr CSRReader) (tlsc *tls.Config, keypem, certpem []byte, err error) {
	keypem, err = s.NewKey()
	if err != nil {
		return
	}
	certpem, err = s.NewCertificateCSR(csr, keypem)
	if err != nil {
		return
	}
	tlscert, err := tls.X509KeyPair(certpem, keypem)
	if err != nil {
		return
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(s.cfg.Rootcert); !ok {
		return nil, nil, nil, errors.New("invalid CA")
	}

	tlsc = &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{tlscert},
		ClientCAs:    certPool,
	}
	return
}
