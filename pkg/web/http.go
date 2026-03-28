package web

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"charm.land/log/v2"
	"github.com/charmbracelet/soft-serve/pkg/config"
)

// HTTPServer is an http server.
type HTTPServer struct {
	ctx context.Context
	cfg *config.Config

	Server *http.Server
}

// NewHTTPServer creates a new HTTP server.
func NewHTTPServer(ctx context.Context) (*HTTPServer, error) {
	cfg := config.FromContext(ctx)
	logger := log.FromContext(ctx)
	s := &HTTPServer{
		ctx: ctx,
		cfg: cfg,
		Server: &http.Server{
			Addr:              cfg.HTTP.ListenAddr,
			Handler:           NewRouter(ctx),
			ReadHeaderTimeout: time.Second * 10,
			IdleTimeout:       time.Second * 10,
			MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
			ErrorLog:          logger.StandardLog(log.StandardLogOptions{ForceLevel: log.ErrorLevel}),
		},
	}

	return s, nil
}

// SetTLSConfig sets the TLS configuration for the HTTP server.
func (s *HTTPServer) SetTLSConfig(tlsConfig *tls.Config) {
	s.Server.TLSConfig = tlsConfig
}

// Close closes the HTTP server.
func (s *HTTPServer) Close() error {
	return s.Server.Close()
}

// ListenAndServe starts the HTTP server.
func (s *HTTPServer) ListenAndServe() error {
	if s.Server.TLSConfig != nil {
		return s.Server.ListenAndServeTLS("", "")
	}
	return s.Server.ListenAndServe()
}

// Serve accepts connections on l. If TLS is configured, incoming connections
// are wrapped with TLS using the server's TLSConfig.
//
// When TLS is active, ServeTLS is called with empty cert/key file paths.
// This is safe only when TLSConfig.GetCertificate is set (which is always
// the case when soft-serve wires up CertReloader). Do not call Serve with
// TLSConfig set unless GetCertificate or Certificates is populated —
// ServeTLS will fail with an opaque TLS error if neither is present.
func (s *HTTPServer) Serve(l net.Listener) error {
	if s.Server.TLSConfig != nil {
		return s.Server.ServeTLS(l, "", "")
	}
	return s.Server.Serve(l)
}

// Shutdown gracefully shuts down the HTTP server.
func (s *HTTPServer) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}
