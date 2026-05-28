package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	code := flag.String("code", "", "shared secret (required)")
	bind := flag.String("bind", ":8081", "local address to bind")
	rendezvous := flag.String("rendezvous", wormhole.DefaultRendezvousURL, "rendezvous URL")
	transit := flag.String("transit", wormhole.DefaultTransitRelayAddress, "transit relay")
	flag.Parse()

	if *code == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -code <secret> [-bind addr]\n", os.Args[0])
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
	log.Printf("joined tunnel, binding %s", *bind)

	go func() {
		if err := t.Forward(ctx, *bind); err != nil && ctx.Err() == nil {
			log.Fatalf("bind: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://%s/", *bind))
	if err != nil {
		log.Fatalf("GET: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("read body: %v", err)
	}
	log.Printf("GET response: %s", string(body))
}
