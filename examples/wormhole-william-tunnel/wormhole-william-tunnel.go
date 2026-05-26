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
	mode := flag.String("mode", "", "serve or forward")
	code := flag.String("code", "", "wormhole code (e.g. 4-sodium-bottle)")
	local := flag.String("local", ":8080", "local address")
	remote := flag.String("remote", ":8080", "remote address (forward mode)")
	rendezvous := flag.String("rendezvous", wormhole.DefaultRendezvousURL, "rendezvous mailbox URL")
	transit := flag.String("transit", wormhole.DefaultTransitRelayAddress, "transit relay address")
	flag.Parse()

	if *mode == "" || *code == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -mode <serve|forward> -code <code> [-local addr] [-remote addr]\n", os.Args[0])
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := wormhole.Client{
		RendezvousURL:       *rendezvous,
		TransitRelayAddress: *transit,
	}

	switch *mode {
	case "serve":
		serve(ctx, &c, *code, *local)
	case "forward":
		forward(ctx, &c, *code, *local, *remote)
	default:
		log.Fatalf("unknown mode %q, use serve or forward", *mode)
	}
}

func serve(ctx context.Context, c *wormhole.Client, code, localAddr string) {
	t, err := c.CreateTunnelWithCode(ctx, code)
	if err != nil {
		log.Fatalf("create tunnel: %v", err)
	}
	defer t.Close()

	log.Printf("tunnel created with code %q, serving %s", code, localAddr)
	if err := t.Serve(ctx, localAddr); err != nil && ctx.Err() == nil {
		log.Fatalf("serve: %v", err)
	}
}

func forward(ctx context.Context, c *wormhole.Client, code, localAddr, remoteAddr string) {
	t, err := c.JoinTunnel(ctx, code)
	if err != nil {
		log.Fatalf("join tunnel: %v", err)
	}
	defer t.Close()

	log.Printf("joined tunnel with code %q, forwarding %s -> %s", code, localAddr, remoteAddr)
	if err := t.Forward(ctx, localAddr, remoteAddr); err != nil && ctx.Err() == nil {
		log.Fatalf("forward: %v", err)
	}
}
