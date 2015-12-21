package main

import (
	"time"

	"github.com/flynn/flynn/Godeps/_workspace/src/github.com/flynn/go-docopt"
	log "github.com/flynn/flynn/Godeps/_workspace/src/gopkg.in/inconshreveable/log15.v2"
	"github.com/flynn/flynn/installer"
)

func init() {
	register("install", runInstaller, `
usage: flynn install

Starts server for installer web interface.

Examples:

	$ flynn install
`)
}

func runInstaller(args *docopt.Args) error {
	logger := log.New()
	i := installer.NewInstaller(logger)
	lastEventID := installer.EventID(time.Now())
	go func() {
		events := make(chan *installer.Event)
		sub := i.SubscribeEvents(events, lastEventID)
		defer i.UnsubscribeEvents(sub)
		for event := range events {
			switch event.Type {
			case "error":
				logger.Error(event.Description, "cluster_id", event.ClusterID)
			case "log":
				logger.Info(event.Description, "cluster_id", event.ClusterID)
			}
		}
	}()
	return i.ServeHTTP()
}
