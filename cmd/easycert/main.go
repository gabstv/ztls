package main

import (
	"context"
	"io/ioutil"
	"os"

	"github.com/gabstv/ztls/api/ztls"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "endpoint",
			Value: "https://ztls.gabs.dev",
		},
		cli.StringFlag{
			Name: "apikey",
		},
		cli.StringFlag{
			Name:  "key-out, key",
			Value: "key.pem",
		},
		cli.StringFlag{
			Name:  "cert-out, cert",
			Value: "cert.pem",
		},
		cli.StringFlag{
			Name: "common-name",
		},
	}

	app.Action = run

	app.RunAndExitOnError()
}

func run(c *cli.Context) error {
	cl := &ztls.Client{
		Endpoint: c.String("endpoint"),
		APIKey:   c.String("apikey"),
	}

	keybytes, err := cl.NewKey()

	if err != nil {
		return err
	}

	cname := c.String("common-name")

	if cname == "" {
		cname = os.Getenv("USER")
		if cname != "" {
			cname = cname + ".localhost"
		} else {
			cname = "grpc-client.localhost"
		}
	}

	csrb, err := cl.NewCSR(ztls.NewCSRInput{
		CommonName: cname,
	}, keybytes)

	if err != nil {
		return err
	}

	certb, err := cl.NewCertificate(context.Background(), csrb)

	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(c.String("key-out"), keybytes, 0700); err != nil {
		return err
	}
	if err := ioutil.WriteFile(c.String("cert-out"), certb, 0700); err != nil {
		return err
	}

	println(c.String("key-out"))
	println(c.String("cert-out"))
	return nil
}
