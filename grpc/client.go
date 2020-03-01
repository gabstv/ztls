package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/gabstv/ztls/api/ztls"
	"github.com/gabstv/ztls/embedded"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type DialInput struct {
	ServerName    string
	ServerAddress string
	ClientName    string
	Options       []grpc.DialOption
}

type DialWithConfigPEMInput struct {
	DialInput
	ConfigPEM []byte
}

type DialWithEmbeddedInput struct {
	DialInput
	Server *embedded.Server
}

func DialWithConfigPEM(ctx context.Context, input DialWithConfigPEMInput) (*grpc.ClientConn, error) {
	s, err := embedded.NewWithConfig(ctx, input.ConfigPEM)
	if err != nil {
		return nil, err
	}
	return DialWithEmbedded(DialWithEmbeddedInput{
		DialInput: input.DialInput,
		Server:    s,
	})
}

func DialWithEmbedded(input DialWithEmbeddedInput) (*grpc.ClientConn, error) {
	svname := input.ServerName
	if svname == "" {
		svname = input.ServerAddress
	}
	clname := input.ClientName
	if clname == "" {
		clname = "grpc-client"
	}
	//
	cfg, _, _, err := input.Server.NewClientAuto(svname, &embedded.CSRJson{
		CommonName: clname,
	})
	if err != nil {
		return nil, err
	}
	opt0 := grpc.WithTransportCredentials(credentials.NewTLS(cfg))
	optx := make([]grpc.DialOption, 1)
	optx[0] = opt0
	if input.Options != nil {
		optx = append(optx, input.Options...)
	}
	return grpc.Dial(input.ServerAddress, optx...)
}

type DialWithRestServerInput struct {
	DialInput
	RestAPIKey   string
	RestEndpoint string
	KeyPEM       []byte
}

func DialWithRestServer(ctx context.Context, input DialWithRestServerInput) (*grpc.ClientConn, error) {
	cl := &ztls.Client{
		APIKey:   input.RestAPIKey,
		Endpoint: input.RestEndpoint,
	}
	key := input.KeyPEM
	if key == nil {
		var err error
		key, err = cl.NewKey()
		if err != nil {
			return nil, err
		}
	}
	//
	ca, err := cl.GetCA(ctx)
	if err != nil {
		return nil, err
	}
	//
	svname := input.ServerName
	if svname == "" {
		svname = input.ServerAddress
	}
	clname := input.ClientName
	if clname == "" {
		clname = "grpc-client"
	}
	//
	csr, err := cl.NewCSR(ztls.CommonName(clname), key)
	if err != nil {
		return nil, err
	}
	cert, err := cl.NewCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}
	//
	tlscert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("invalid CA")
	}

	tlsc := &tls.Config{
		ServerName:   svname,
		Certificates: []tls.Certificate{tlscert},
		RootCAs:      certPool,
	}
	optx := make([]grpc.DialOption, 1)
	optx[0] = grpc.WithTransportCredentials(credentials.NewTLS(tlsc))
	if input.Options != nil {
		optx = append(optx, input.Options...)
	}
	return grpc.Dial(input.ServerAddress, optx...)
}
