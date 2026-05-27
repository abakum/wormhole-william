package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	code := flag.String("code", "", "shared secret (leave empty to generate)")
	local := flag.String("local", ":8080", "local address to serve")
	rendezvous := flag.String("rendezvous", wormhole.DefaultRendezvousURL, "rendezvous URL")
	transit := flag.String("transit", wormhole.DefaultTransitRelayAddress, "transit relay")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := wormhole.Client{
		RendezvousURL:       *rendezvous,
		TransitRelayAddress: *transit,
	}

	log.Printf("rendezvous=%s transit=%s", *rendezvous, *transit)

	generatedCode, t, err := c.CreateTunnel(ctx, *code)
	if err != nil {
		log.Fatalf("create tunnel: %v", err)
	}
	log.Printf("wormhole code: %s", generatedCode)
	defer t.Close()
	log.Printf("tunnel created, serving %s", *local)
	if err := t.Serve(ctx, *local); err != nil && ctx.Err() == nil {
		log.Fatalf("serve: %v", err)
	}
}
