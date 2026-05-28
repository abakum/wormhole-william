package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/psanford/wormhole-william/wormhole"
)

func main() {
	code := flag.String("code", "", "shared secret (leave empty to generate)")
	dial := flag.String("dial", ":8080", "address to dial")
	rendezvous := flag.String("rendezvous", wormhole.DefaultRendezvousURL, "rendezvous URL")
	transit := flag.String("transit", wormhole.DefaultTransitRelayAddress, "transit relay")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello tunnel\n")
	})
	go http.ListenAndServe(*dial, nil)

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
	log.Printf("tunnel created, dialing %s", *dial)
	if err := t.Serve(ctx, *dial); err != nil && ctx.Err() == nil {
		log.Fatalf("dial: %v", err)
	}
}
