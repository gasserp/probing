package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gasserp/probing/core"
	"github.com/gasserp/probing/store"
)

func main() {
	configPath := flag.String("config", "", "path to the agent JSON configuration")
	flag.Parse()
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: probing-agent -config <path>")
		os.Exit(2)
	}
	if err := run(*configPath); err != nil {
		log.Printf("probing-agent stopped: %v", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	configuration, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	sshClassifier, httpClassifier, restoreWindow, err := configuration.classifiers()
	if err != nil {
		return err
	}
	state, err := store.Open(configuration.DatabasePath)
	if err != nil {
		return err
	}
	defer state.Close()

	processor, err := core.NewProcessor(state, sshClassifier, httpClassifier)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := processor.RestoreSSH(ctx, time.Now().UTC().Add(-restoreWindow), sshClassifier.MaxTotalEvents()); err != nil {
		return err
	}
	supervisor, err := core.NewSupervisor(processor)
	if err != nil {
		return err
	}
	return supervisor.Run(ctx, configuration.Adapters)
}
