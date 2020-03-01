package main

import (
	"context"
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
		cli.StringFlag{
			Name:   "svc-key",
			EnvVar: "SVC_KEY",
			Usage:  "The root key (PEM). " + clix.ContentUsage(),
		},
		cli.StringFlag{
			Name:   "svc-cert",
			EnvVar: "SVC_CERT",
			Usage:  "The root certificate (CA PEM). " + clix.ContentUsage(),
		},
		cli.StringFlag{
			Name:   "apikey",
			EnvVar: "APIKEY",
			Usage:  "API Key for authenticated rest routes",
		},
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:        "generate",
			ShortName:   "gen",
			Description: "generate a new master key and certificate authority",
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
	}

	app.Action = run

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
		configd = genconfig()
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

func genconfig() []byte {
	key, err := pkix.NewKey(4096)
	if err != nil {
		panic(err)
	}
	ca, err := pkix.NewCACertificate(key)
	if err != nil {
		panic(err)
	}
	u, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	cfg := &embedded.Config{
		Rootcert: ca,
		Rootkey:  key,
		Apikey:   u.String(),
	}
	println("####")
	println("####")
	println("CONFIG GENERATED")
	pem := cfg.Marshal(map[string]string{
		"Generator": "ztls CLI",
		"Expires":   time.Now().AddDate(20, 0, 0).String(),
		"X-API-KEY": u.String(),
	})
	println("")
	println(string(pem))
	println("")
	return pem
}
