// netship is a self-baselining egress monitor with a web dashboard.
//
// One binary: run it, the dashboard serves, the watcher attaches. Config lives in
// a JSON file that gets written with working defaults on first run, and the demo
// is behind a button. Everything that is not this file is in the netship package.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Bittu5134/NetShip/netship"
)

const banner = `netship - what is new on this machine's network edge`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "netship: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, cfgPath := netship.LoadConfig()

	store, err := netship.OpenStore(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("cannot open baseline: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	enr := netship.NewEnricher(!cfg.Enrich)
	enr.Start(ctx)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("cannot listen on %s (see %s): %w", cfg.Listen, cfgPath, err)
	}

	fmt.Printf("%s\n\n  dashboard  http://%s\n  config     %s\n  baseline   %s (%d binaries)\n  poll       every %s, silent for the first %s\n\n",
		banner, cfg.Listen, cfgPath, cfg.DataDir, store.Baselines(), cfg.Interval, cfg.Learning)

	app := netship.NewApp(store, enr, ctx, cfg.IntervalDuration(), cfg.LearningDuration(), cfg.Enrich)

	serveErr := app.Serve(ln)
	if saveErr := store.Save(); saveErr != nil {
		fmt.Fprintf(os.Stderr, "netship: saving baseline: %v\n", saveErr)
	}
	if serveErr != nil && !strings.Contains(serveErr.Error(), "Server closed") {
		return serveErr
	}
	return nil
}
