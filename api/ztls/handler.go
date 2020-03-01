package ztls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// CredentialsOutput is obtained from ServerCredentials or ClientCredentials
type CredentialsOutput struct {
	Transport credentials.TransportCredentials
	CA        []byte
	Cert      []byte
	Key       []byte
}

// Creds returns the correct grpc.ServerOption to use with grpc.NewServer
func Creds(cro *CredentialsOutput) grpc.ServerOption {
	return grpc.Creds(cro.Transport)
}

// ServerCredentials creates the credentials necessary to run a secure gRPC service
func ServerCredentials(ctx context.Context, authType tls.ClientAuthType, commonName string) (*CredentialsOutput, error) {
	return ServerCredentialsWithClient(ctx, authType, commonName, DefaultClient)
}

func ServerCredentialsWithClient(ctx context.Context, authType tls.ClientAuthType, commonName string, cl *Client) (*CredentialsOutput, error) {
	ca, err := cl.GetCA(ctx)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("could not parse CA certificate")
	}
	//
	key, err := cl.NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := cl.NewCSR(NewCSRInput{
		CommonName: commonName,
	}, key)
	if err != nil {
		return nil, err
	}
	cert, err := cl.NewCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}
	//
	v, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	outp := &CredentialsOutput{
		CA:   ca,
		Key:  key,
		Cert: cert,
	}

	outp.Transport = credentials.NewTLS(&tls.Config{
		ClientAuth:   authType,
		Certificates: []tls.Certificate{v},
		ClientCAs:    certPool,
	})

	return outp, nil
}

// ClientCredentials creates the credentials to connect to a secure gRPC service
func ClientCredentials(ctx context.Context, commonName, remoteCommonName string) (*CredentialsOutput, error) {
	return ClientCredentialsWithClient(ctx, commonName, remoteCommonName, DefaultClient)
}

func ClientCredentialsWithClient(ctx context.Context, commonName, remoteCommonName string, cl *Client) (*CredentialsOutput, error) {
	ca, err := cl.GetCA(ctx)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("could not parse CA certificate")
	}
	//
	key, err := cl.NewKey()
	if err != nil {
		return nil, err
	}
	csr, err := cl.NewCSR(NewCSRInput{
		CommonName: commonName,
	}, key)
	if err != nil {
		return nil, err
	}
	cert, err := cl.NewCertificate(ctx, csr)
	if err != nil {
		return nil, err
	}
	//
	v, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	outp := &CredentialsOutput{
		CA:   ca,
		Key:  key,
		Cert: cert,
	}

	outp.Transport = credentials.NewTLS(&tls.Config{
		ServerName:   remoteCommonName,
		Certificates: []tls.Certificate{v},
		RootCAs:      certPool,
	})
	return outp, nil
}
