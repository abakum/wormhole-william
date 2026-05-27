package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	code := flag.String("code", "", "shared secret (required)")
	local := flag.String("local", ":8080", "local address to forward")
	rendezvous := flag.String("rendezvous", wormhole.DefaultRendezvousURL, "rendezvous URL")
	transit := flag.String("transit", wormhole.DefaultTransitRelayAddress, "transit relay")
	flag.Parse()

	if *code == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -code <secret> [-local addr]\n", os.Args[0])
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := wormhole.Client{
		RendezvousURL:       *rendezvous,
		TransitRelayAddress: *transit,
	}

	log.Printf("rendezvous=%s transit=%s", *rendezvous, *transit)

	_, t, err := c.JoinTunnel(ctx, *code)
	if err != nil {
		log.Fatalf("join tunnel: %v", err)
	}
	defer t.Close()
	log.Printf("joined tunnel, forwarding %s", *local)
	if err := t.Forward(ctx, *local); err != nil && ctx.Err() == nil {
		log.Fatalf("forward: %v", err)
	}
}
