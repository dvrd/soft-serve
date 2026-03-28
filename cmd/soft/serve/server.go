package serve

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	"charm.land/log/v2"

	"github.com/charmbracelet/soft-serve/pkg/backend"
	"github.com/charmbracelet/soft-serve/pkg/config"
	"github.com/charmbracelet/soft-serve/pkg/cron"
	"github.com/charmbracelet/soft-serve/pkg/daemon"
	"github.com/charmbracelet/soft-serve/pkg/db"
	"github.com/charmbracelet/soft-serve/pkg/jobs"
	sshsrv "github.com/charmbracelet/soft-serve/pkg/ssh"
	"github.com/charmbracelet/soft-serve/pkg/stats"
	"github.com/charmbracelet/soft-serve/pkg/web"
	"github.com/charmbracelet/ssh"
	"golang.org/x/sync/errgroup"
)

// Server is the Soft Serve server.
type Server struct {
	SSHServer   *sshsrv.SSHServer
	GitDaemon   *daemon.GitDaemon
	HTTPServer  *web.HTTPServer
	StatsServer *stats.StatsServer
	CertLoader  *CertReloader
	Cron        *cron.Scheduler
	Config      *config.Config
	Backend     *backend.Backend
	DB          *db.DB

	logger *log.Logger
	ctx    context.Context
}

// NewServer returns a new *Server configured to serve Soft Serve. The SSH
// server key-pair will be created if none exists.
// It expects a context with *backend.Backend, *db.DB, *log.Logger, and
// *config.Config attached.
func NewServer(ctx context.Context) (*Server, error) {
	var err error
	cfg := config.FromContext(ctx)
	be := backend.FromContext(ctx)
	db := db.FromContext(ctx)
	logger := log.FromContext(ctx).WithPrefix("server")
	srv := &Server{
		Config:  cfg,
		Backend: be,
		DB:      db,
		logger:  log.FromContext(ctx).WithPrefix("server"),
		ctx:     ctx,
	}

	// Add cron jobs.
	sched := cron.NewScheduler(ctx)
	for n, j := range jobs.List() {
		id, err := sched.AddFunc(j.Runner.Spec(ctx), j.Runner.Func(ctx))
		if err != nil {
			logger.Warn("error adding cron job", "job", n, "err", err)
		}

		j.ID = id
	}

	srv.Cron = sched

	srv.SSHServer, err = sshsrv.NewSSHServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("create ssh server: %w", err)
	}

	srv.GitDaemon, err = daemon.NewGitDaemon(ctx)
	if err != nil {
		return nil, fmt.Errorf("create git daemon: %w", err)
	}

	srv.HTTPServer, err = web.NewHTTPServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("create http server: %w", err)
	}

	srv.StatsServer, err = stats.NewStatsServer(ctx)
	if err != nil {
		return nil, fmt.Errorf("create stats server: %w", err)
	}

	if cfg.HTTP.TLSKeyPath != "" && cfg.HTTP.TLSCertPath != "" {
		srv.CertLoader, err = NewCertReloader(cfg.HTTP.TLSCertPath, cfg.HTTP.TLSKeyPath, logger)
		if err != nil {
			return nil, fmt.Errorf("create cert reloader: %w", err)
		}

		srv.HTTPServer.SetTLSConfig(&tls.Config{
			GetCertificate: srv.CertLoader.GetCertificateFunc(),
		})
	}

	return srv, nil
}

// ReloadCertificates reloads the TLS certificates for the HTTP server.
func (s *Server) ReloadCertificates() error {
	if s.CertLoader == nil {
		return nil
	}
	return s.CertLoader.Reload()
}

// Start starts the SSH server.
func (s *Server) Start() error {
	// Pre-bind all listeners synchronously before starting any goroutines.
	// This ensures that a bind failure (e.g. EACCES on a privileged port) is
	// returned immediately to the caller rather than being lost inside a
	// goroutine that the errgroup can never cancel.
	type serveFunc func(net.Listener) error

	type server struct {
		addr    string
		label   string
		serve   serveFunc
		closed  error // sentinel that means "server shut down cleanly"
		enabled bool
	}

	srvs := []server{
		{
			addr:    s.Config.SSH.ListenAddr,
			label:   "SSH server",
			serve:   s.SSHServer.Serve,
			closed:  ssh.ErrServerClosed,
			enabled: s.Config.SSH.Enabled,
		},
		{
			addr:    s.Config.Git.ListenAddr,
			label:   "Git daemon",
			serve:   s.GitDaemon.Serve,
			closed:  daemon.ErrServerClosed,
			enabled: s.Config.Git.Enabled,
		},
		{
			addr:    s.Config.HTTP.ListenAddr,
			label:   "HTTP server",
			serve:   s.HTTPServer.Serve,
			closed:  http.ErrServerClosed,
			enabled: s.Config.HTTP.Enabled,
		},
		{
			addr:    s.Config.Stats.ListenAddr,
			label:   "Stats server",
			serve:   s.StatsServer.Serve,
			closed:  http.ErrServerClosed,
			enabled: s.Config.Stats.Enabled,
		},
	}

	// Bind all listeners before launching any goroutines.
	// If a bind fails, close the ones we already opened so their ports are
	// released immediately (important for rapid restart scenarios).
	var listeners []net.Listener
	for _, srv := range srvs {
		if !srv.enabled {
			continue
		}
		l, err := net.Listen("tcp", srv.addr)
		if err != nil {
			for _, open := range listeners {
				open.Close() //nolint:errcheck
			}
			return fmt.Errorf("%s: %w", srv.label, err)
		}
		listeners = append(listeners, l)
	}

	errg, _ := errgroup.WithContext(s.ctx)

	li := 0
	for _, srv := range srvs {
		if !srv.enabled {
			continue
		}
		l := listeners[li]
		li++
		srv := srv // for Go versions < 1.22
		errg.Go(func() error {
			// Log the real bound address, which differs from srv.addr when
			// the port was 0 (OS-assigned) — common in tests.
			s.logger.Print("Starting "+srv.label, "addr", l.Addr().String())
			if err := srv.serve(l); !errors.Is(err, srv.closed) {
				return err
			}
			return nil
		})
	}

	errg.Go(func() error {
		s.Cron.Start()
		return nil
	})
	return errg.Wait()
}

// Shutdown lets the server gracefully shutdown.
func (s *Server) Shutdown(ctx context.Context) error {
	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return s.GitDaemon.Shutdown(ctx)
	})
	errg.Go(func() error {
		return s.HTTPServer.Shutdown(ctx)
	})
	errg.Go(func() error {
		return s.SSHServer.Shutdown(ctx)
	})
	errg.Go(func() error {
		return s.StatsServer.Shutdown(ctx)
	})
	errg.Go(func() error {
		for _, j := range jobs.List() {
			s.Cron.Remove(j.ID)
		}
		s.Cron.Stop()
		return nil
	})
	// defer s.DB.Close() // nolint: errcheck
	return errg.Wait()
}

// Close closes the SSH server.
func (s *Server) Close() error {
	var errg errgroup.Group
	errg.Go(s.GitDaemon.Close)
	errg.Go(s.HTTPServer.Close)
	errg.Go(s.SSHServer.Close)
	errg.Go(s.StatsServer.Close)
	errg.Go(func() error {
		s.Cron.Stop()
		return nil
	})
	// defer s.DB.Close() // nolint: errcheck
	return errg.Wait()
}
