package grpc

import (
	"context"

	"github.com/gabstv/ztls/embedded"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type NewServerInput struct {
	CommonName string
	Domains    []string
	IPs        []string
	Options    []grpc.ServerOption
}

type NewServerWithConfigPEMInput struct {
	NewServerInput
	ConfigPEM []byte
}

func NewServerWithConfigPEM(ctx context.Context, input NewServerWithConfigPEMInput) (*grpc.Server, error) {
	s, err := embedded.NewWithConfig(ctx, input.ConfigPEM)
	if err != nil {
		return nil, err
	}
	return NewServerWithEmbedded(NewServerWithEmbeddedInput{
		NewServerInput: input.NewServerInput,
		Server:         s,
	})
}

type NewServerWithEmbeddedInput struct {
	NewServerInput
	Server *embedded.Server
}

func NewServerWithEmbedded(input NewServerWithEmbeddedInput) (*grpc.Server, error) {
	tlsc, _, _, err := input.Server.NewServerAuto(&embedded.CSRJson{
		CommonName: input.CommonName,
		Domains:    input.Domains,
		IPs:        input.IPs,
	})
	if err != nil {
		return nil, err
	}
	//
	optx := make([]grpc.ServerOption, 1)
	optx[0] = grpc.Creds(credentials.NewTLS(tlsc))
	if input.Options != nil {
		optx = append(optx, input.Options...)
	}
	//
	return grpc.NewServer(optx...), nil
}
