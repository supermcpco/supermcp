package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/supermcpco/supermcp/internal/catalog"
	"github.com/supermcpco/supermcp/internal/config"
	"github.com/supermcpco/supermcp/internal/httpapi"
	"github.com/supermcpco/supermcp/internal/invoke"
	"github.com/supermcpco/supermcp/internal/store"
	"github.com/supermcpco/supermcp/internal/telemetry"
)

func serveCmd(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(version)
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.MigrateOnStart {
		log.Warn("SUPERMCP_MIGRATE_ON_START is set; running migrations from serve (single-replica deployments only)")
		mst, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{})
		if err != nil {
			return err
		}
		err = mst.Migrate(ctx, true)
		mst.Close()
		if err != nil {
			return err
		}
	}
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{AppRole: true})
	if err != nil {
		return err
	}
	defer st.Close()

	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	log.Info("catalog loaded", "adapters", cat.Index.Count, "hash", cat.Index.CatalogHash)

	deps, jobs, cleanup, err := build(ctx, cfg, log, st, cat)
	if err != nil {
		return err
	}
	defer cleanup()
	// Shipping and pruning the audit stream run beside the server, one
	// replica at a time.
	jobs.start(ctx)
	handler, _ := httpapi.New(deps)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       65 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	// The exposition publishes the shape of the estate, so it lives on the
	// admin listener rather than beside the public API.
	var admin *http.Server
	if cfg.AdminListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", deps.Metrics.Handler())
		admin = &http.Server{Addr: cfg.AdminListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("admin listener", "addr", cfg.AdminListen)
			if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("admin listener stopped", "err", err)
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Listen, "public_url", cfg.PublicURL.String(), "dev", cfg.Dev)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if admin != nil {
		_ = admin.Shutdown(shutdownCtx)
	}
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("forced shutdown", "err", err)
		return err
	}
	return nil
}

func migrateCmd(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	wait := fs.Bool("wait-lock", true, "block until the migration lock is free (false = fail fast)")
	status := fs.Bool("status", false, "print schema version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadOffline(version)
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel, cfg.LogFormat, cfg.Version)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.MaintDatabaseURL, log, store.Options{})
	if err != nil {
		return err
	}
	defer st.Close()
	if *status {
		have, err := st.SchemaVersion(ctx)
		if err != nil {
			have = 0
		}
		want, err := store.LatestVersion()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "schema version: %d (binary expects %d)\n", have, want)
		return nil
	}
	return st.Migrate(ctx, *wait)
}

// openapiCmd prints the OpenAPI document without touching a database, for
// client generation in CI.
func openapiCmd(args []string) error {
	fs := flag.NewFlagSet("openapi", flag.ContinueOnError)
	format := fs.String("format", "json", "json | yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := &config.Config{Version: version, PublicURL: mustURL("https://supermcp.example"), LogLevel: "error", LogFormat: "json"}
	log := telemetry.NewLogger("error", "json", version)
	cat, err := catalog.Load()
	if err != nil {
		return err
	}
	// The document describes the surface a running instance serves, so the
	// routes that only exist when a collaborator is present have to be
	// given one. Without a blob store, /api/v1/blobs/{id} was missing from
	// the document and therefore from the generated client.
	blobs := invoke.NewMemoryBlobStore(invoke.BlobOptions{BaseURL: cfg.PublicURL.String()})
	_, api := httpapi.New(httpapi.Deps{Config: cfg, Log: log, Catalog: cat, Blobs: blobs})
	var out []byte
	if *format == "yaml" {
		out, err = api.OpenAPI().YAML()
	} else {
		out, err = api.OpenAPI().MarshalJSON()
	}
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(out, '\n'))
	return err
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
