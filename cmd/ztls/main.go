package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/gabstv/ztls/embedded"
	"github.com/gabstv/ztls/internal/clix"
	"github.com/gabstv/ztls/internal/metadata"
	"github.com/gabstv/ztls/internal/pkix"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "ztls"
	app.Author = "Gabriel Ochsenhofer"
	app.Version = metadata.Version()

	//app.ArgsUsage

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "loglevel, ll",
			EnvVar: "LOGLEVEL",
			Value:  "warn",
		},
		cli.StringFlag{
			Name:   "listen",
			EnvVar: "LISTEN",
			Value:  ":8080",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:        "generate",
			ShortName:   "gen",
			Description: "generate a new master key and certificate authority",
			Usage:       "generate a new key and CA cert",
			Action:      cmdgen,
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "keysize, ksz",
					Usage: "Key size (bits): 2048, 4096, 8192",
					Value: 4096,
				},
				cli.StringFlag{
					Name:  "output-dir, odir",
					Usage: "Output directory",
				},
				cli.StringFlag{
					Name:  "key-output-name, kout",
					Usage: "Key output name",
					Value: "ca-key.pem",
				},
				cli.StringFlag{
					Name:  "cert-output-name, caout",
					Usage: "Certificate output name",
					Value: "ca-cert.pem",
				},
			},
		},
		cli.Command{
			Name:        "serve",
			ShortName:   "s",
			Usage:       "Host a rest server",
			Description: "Host a rest server",
			Action:      cmdserve,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "config",
					EnvVar: "ZTLS_CONFIG",
					Usage:  "The configuration to boot ztls rest server. " + clix.ContentUsage(),
				},
				cli.StringFlag{
					Name:   "listen",
					EnvVar: "LISTEN",
					Value:  ":8080",
				},
			},
		},
		cli.Command{
			Name:      "config",
			ShortName: "cfg",
			Usage:     "config file manipulation",
			Subcommands: []cli.Command{
				cli.Command{
					Name:   "new",
					Usage:  "create a new ZTLS config file",
					Action: cmdcfgnew,
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "key",
							Usage: "The root key (PEM). " + clix.ContentUsage(),
						},
						cli.StringFlag{
							Name:  "cert",
							Usage: "The root certificate (CA PEM). " + clix.ContentUsage(),
						},
						cli.StringFlag{
							Name:  "apikey",
							Usage: "API Key for authenticated rest routes",
						},
						cli.StringFlag{
							Name:  "output, o",
							Usage: "output file path",
							Value: "ztlsconfig.txt",
						},
						cli.BoolFlag{
							Name:  "stdout",
							Usage: "output config to standard output",
						},
					},
				},
			},
		},
		cli.Command{
			Name: "util",
			Subcommands: cli.Commands{
				cli.Command{
					Name:      "base64decode",
					ShortName: "b64d",
					Action:    cmdutilbase64decode,
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "file",
							Usage: "the input file (default: read data from arg[1])",
						},
						cli.StringFlag{
							Name:  "output",
							Usage: "output file",
						},
						cli.BoolFlag{
							Name:  "stdout",
							Usage: "output to stdout",
						},
					},
				},
			},
		},
	}

	//app.Action = run

	if err := app.Run(os.Args); err != nil {
		if clierr, ok := err.(*cli.ExitError); ok {
			log.Error().Err(err).Int("exit_code", clierr.ExitCode()).Msg("will exit")
			os.Exit(clierr.ExitCode())
		}
		log.Error().Err(err).Msg("will exit")
	}
}

func run(c *cli.Context) error {
	logsetup(c)

	//c.App.ToMarkdown()

	return nil
}

func logsetup(c *cli.Context) {
	ll := strings.ToLower(c.GlobalString("loglevel"))
	switch ll {
	case "error", "err", "e":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "warning", "warn", "w":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "information", "info", "i":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "debug", "dbg", "d":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

func cmdgen(c *cli.Context) error {
	logsetup(c)

	keysz := c.Int("keysize")

	log.Info().Int("keysize", keysz).Msg("generating RSA PRIVATE KEY")

	keypem, err := pkix.NewKey(keysz)
	if err != nil {
		return cli.NewExitError(err.Error(), 11)
	}

	log.Info().Int("keysize", keysz).Msg("generating CA CERTIFICATE")

	certpem, err := pkix.NewCACertificate(keypem)
	if err != nil {
		return cli.NewExitError(err.Error(), 11)
	}

	keypath := c.String("key-output-name")
	certpath := c.String("cert-output-name")

	if basedir := c.String("output-dir"); basedir != "" {
		keypath = filepath.Join(basedir, keypath)
		certpath = filepath.Join(basedir, certpath)
	}

	if err := ioutil.WriteFile(keypath, keypem, 0740); err != nil {
		return cli.NewExitError(err.Error(), 11)
	}
	log.Debug().Str("path", keypath).Msg("key written")

	if err := ioutil.WriteFile(certpath, certpem, 0740); err != nil {
		return cli.NewExitError(err.Error(), 11)
	}
	log.Debug().Str("path", certpath).Msg("CA cert written")

	return nil
}

func cmdserve(c *cli.Context) error {
	logsetup(c)
	configd := clix.ParseContentValue(c.String("config"), true)
	if configd == nil {
		if c.String("config") != "" {
			return cli.NewExitError("invalid config", 1)
		}
		// create a new config on the spot
		configd = genconfig(nil, nil, "")
		println("####")
		println("####")
		println("CONFIG GENERATED - YOU MUST COPY THIS BELOW:")
		println("")
		println(string(configd))
		println("")
		println("")
		println("")
	}

	ctx, cf := context.WithCancel(context.Background())
	defer cf()

	esv, err := embedded.NewWithConfig(ctx, configd)
	if err != nil {
		return cli.NewExitError("invalid config: "+err.Error(), 1)
	}

	log.Info().Str("listen", c.String("listen")).Msg("ListenAndServe")
	httpch, err := esv.ListenAndServeAsync(ctx, c.String("listen"), time.Second*3)
	if err != nil {
		return cli.NewExitError("HTTP: "+err.Error(), 2)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	z := <-sig
	log.Warn().Msg("received signal: " + z.String())
	cf()
	<-httpch
	log.Warn().Msg("rest server shutdown")
	return nil
}

func cmdcfgnew(c *cli.Context) error {
	logsetup(c)
	var key, cert []byte
	var apikey string
	if vv := c.String("key"); vv != "" {
		if v := clix.ParseContentValue(vv, true); v != nil {
			key = v
		}
	}
	if vv := c.String("cert, ca"); vv != "" {
		if v := clix.ParseContentValue(vv, true); v != nil {
			cert = v
		}
	}
	if vv := c.String("apikey"); vv != "" {
		apikey = vv
	}
	cfgb := genconfig(key, cert, apikey)
	if c.Bool("stdout") {
		print(string(cfgb))
		return nil
	}
	outpfn := c.String("output")
	f, err := os.Create(outpfn)
	if err != nil {
		return err
	}
	defer f.Close()
	rdr := bytes.NewReader(cfgb)
	if _, err := io.Copy(f, rdr); err != nil {
		return err
	}
	return nil
}

func cmdutilbase64decode(c *cli.Context) error {
	logsetup(c)

	var inputdata string
	if v := c.String("file"); v != "" {
		bb, err := ioutil.ReadFile(v)
		if err != nil {
			return err
		}
		inputdata = strings.TrimSpace(string(bb))
	} else {
		inputdata = c.Args().First()
	}
	b, err := base64.StdEncoding.DecodeString(inputdata)
	if err != nil {
		return err
	}
	if c.Bool("stdout") {
		os.Stdout.Write(b)
		return nil
	}
	if v := c.String("output"); v != "" {
		f, err := os.Create(v)
		if err != nil {
			return err
		}
		defer f.Close()
		rdr := bytes.NewReader(b)
		_, _ = io.Copy(f, rdr)
		return nil
	}
	return cli.NewExitError("output file not specified", 10)
}

func genconfig(prekey, preca []byte, preapikey string) []byte {
	var key, ca []byte
	var apikey string
	if prekey != nil {
		key = prekey
	} else {
		nkey, err := pkix.NewKey(4096)
		if err != nil {
			panic(err)
		}
		key = nkey
	}
	if preca != nil {
		ca = preca
	} else {
		newca, err := pkix.NewCACertificate(key)
		if err != nil {
			panic(err)
		}
		ca = newca
	}
	if preapikey != "" {
		apikey = preapikey
	} else {
		u, err := uuid.NewRandom()
		if err != nil {
			panic(err)
		}
		apikey = u.String()
	}

	cfg := &embedded.Config{
		Rootcert: ca,
		Rootkey:  key,
		Apikey:   apikey,
	}
	pem := cfg.Marshal(map[string]string{
		"Generator": "ztls CLI",
		"Expires":   time.Now().AddDate(20, 0, 0).String(),
		"X-API-KEY": apikey,
	})
	return pem
}
