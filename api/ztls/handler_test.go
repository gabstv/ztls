package ztls_test

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/gabstv/ztls/api/ztls"
	"google.golang.org/grpc"
)

func TestServer(t *testing.T) {
	ctx, cf := context.WithTimeout(context.Background(), time.Second*25)
	defer cf()
	outp, err := ztls.ServerCredentials(ctx, tls.RequireAndVerifyClientCert, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if outp.CA == nil {
		t.Fail()
	}
	if outp.Key == nil {
		t.Fail()
	}
	if outp.Cert == nil {
		t.Fail()
	}
	if outp.Transport == nil {
		t.Fail()
	}
}

func ExampleCreds() {
	ctx, cf := context.WithTimeout(context.Background(), time.Second*25)
	defer cf()
	xcr, err := ztls.ServerCredentials(ctx, tls.RequireAndVerifyClientCert, "example.com")
	if err != nil {
		println("ERROR: " + err.Error())
		return
	}
	grpcsvr := grpc.NewServer(ztls.Creds(xcr))
	_ = grpcsvr.GetServiceInfo()
	// pb.RegisterSomethingServer(grpcsvr, implementation)
}
