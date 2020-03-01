package embedded

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gabstv/ztls/embedded/middlewares"
	"github.com/gabstv/ztls/embedded/routes"
	"github.com/gabstv/ztls/internal/metadata"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog/log"
)

func (s *Server) httpmust() {
	s.httponce.Do(func() {
		s.httphandler = echo.New()
		s.httphandler.Use(middleware.Recover())
		s.httphandler.Use(middleware.Logger())
		s.httphandler.Use(middleware.BodyLimit("2M"))
		s.httphandler.Use(middleware.Gzip())

		s.registerroutes(s.httphandler)
	})
}

func (s *Server) registerroutes(e *echo.Echo) {
	e.GET("/", routes.Root(metadata.Version()))

	postcsr := func(csr []byte) (cert []byte, err error) {
		return s.NewCertificateRaw(csr)
	}

	// api
	g := e.Group("/1")
	g.POST("/new-certificate", routes.PostCSR(postcsr), middlewares.RateLimiter(4, time.Minute))
	g.POST("/new-server-certificate", routes.PostCSR(postcsr), middlewares.RateLimiter(50, time.Minute), middlewares.APIKey(s.cfg.Apikey))
	g.GET("/ca.crt.pem", routes.GetCA(s.cfg.Rootcert))
}

// ServeHTTP implements `http.Handler` interface, which serves HTTP requests.
func (e *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.httpmust()
	e.httphandler.ServeHTTP(w, r)
}

func (e *Server) ListenAndServeAsync(ctx context.Context, listenaddr string, maxwait time.Duration) (exitch <-chan struct{}, err error) {
	if ctx == nil {
		panic("context is nil")
	}
	hs := &http.Server{
		Addr:           listenaddr,
		Handler:        e,
		ReadTimeout:    time.Second * 30,
		WriteTimeout:   time.Second * 45,
		MaxHeaderBytes: 1024 * 1024,
	}
	//
	ech := make(chan error, 1)
	eopen := true
	var echonce sync.Once
	closech := make(chan struct{}, 1)
	var closechonce sync.Once
	//
	go func() {
		err := hs.ListenAndServe()
		closechonce.Do(func() {
			close(closech)
		})
		if err != nil && eopen {
			ech <- err
		}
	}()
	select {
	case err := <-ech:
		closechonce.Do(func() {
			close(closech)
		})
		return closech, err
	case <-time.After(time.Millisecond * 300):
		// ok
	}
	go func(ctx context.Context, hs *http.Server, ech chan error) {
		select {
		case err := <-ech:
			log.Error().Err(err).Msg("ListenAndServe error")
			if hs != nil {
				ctx2, cf := context.WithTimeout(ctx, maxwait)
				_ = hs.Shutdown(ctx2)
				cf()
			}
		case <-ctx.Done():
			if hs != nil {
				ctx2, cf := context.WithTimeout(ctx, maxwait)
				_ = hs.Shutdown(ctx2)
				cf()
			}
		}
		closechonce.Do(func() {
			close(closech)
		})
		echonce.Do(func() {
			eopen = false
			close(ech)
		})
	}(ctx, hs, ech)
	return closech, nil
}
