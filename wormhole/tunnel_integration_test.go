package wormhole

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
	"github.com/psanford/wormhole-william/wordlist"
)

func TestTunnelCreateJoinServeForward(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	runTunnelNegotiationTest(t, rs.WebSocketURL(), relayServer.addr, relayServer.addr)
}

func TestTunnelRelayNegotiationCreatorCustom(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	runTunnelNegotiationTest(t, rs.WebSocketURL(), relayServer.addr, "")
}

func TestTunnelRelayNegotiationJoinerCustom(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	runTunnelNegotiationTest(t, rs.WebSocketURL(), "", relayServer.addr)
}

func TestTunnelRelayNegotiationCreatorWins(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	runTunnelNegotiationTest(t, rs.WebSocketURL(), relayServer.addr, "0.0.0.0:1")
}

func runTunnelNegotiationTest(t *testing.T, rendezvousURL, creatorRelay, joinerRelay string) {
	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()

	httpLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen for http: %v", err)
	}
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "hello from tunnel")
		}),
	}
	go httpSrv.Serve(httpLis)
	defer httpSrv.Close()
	httpAddr := httpLis.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c0 := Client{
		RendezvousURL:       rendezvousURL,
		TransitRelayAddress: creatorRelay,
	}

	c1 := Client{
		RendezvousURL:       rendezvousURL,
		TransitRelayAddress: joinerRelay,
	}

	nameplate, rc0, sideID0, err := c0.claimOrAllocateNameplate(ctx, "", false)
	if err != nil {
		t.Fatalf("creator claimOrAllocateNameplate: %v", err)
	}

	code := nameplate + "-" + wordlist.ChooseWords(c0.wordCount())
	t.Logf("tunnel code: %s creatorRelay=%q joinerRelay=%q", code, creatorRelay, joinerRelay)

	tunnelCh := make(chan struct{})

	go func() {
		defer close(tunnelCh)
		_, tn, err := c0.establishTunnel(ctx, rc0, sideID0, code, false)
		if err != nil {
			t.Errorf("creator establishTunnel: %v", err)
			return
		}
		defer tn.Close()
		if err := tn.Serve(ctx, httpAddr); err != nil && ctx.Err() == nil {
			t.Errorf("Serve: %v", err)
		}
	}()

	_, rc1, sideID1, err := c1.claimOrAllocateNameplate(ctx, code, true)
	if err != nil {
		t.Fatalf("joiner claimOrAllocateNameplate: %v", err)
	}

	_, tunnelB, err := c1.establishTunnel(ctx, rc1, sideID1, code, true)
	if err != nil {
		t.Fatalf("joiner establishTunnel: %v", err)
	}
	defer tunnelB.Close()

	bindLis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("listen for bind: %v", err)
	}
	bindAddr := bindLis.Addr().String()
	bindLis.Close()

	go tunnelB.Forward(ctx, bindAddr)

	time.Sleep(200 * time.Millisecond)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://%s/hello", bindAddr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	expected := "hello from tunnel"
	if string(body) != expected {
		t.Fatalf("expected %q, got %q", expected, string(body))
	}
	t.Logf("response: %s", string(body))

	cancel()
	<-tunnelCh
}

func TestTunnelBothCreatorsConflict(t *testing.T) {
	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c0 := Client{
		RendezvousURL:       rs.WebSocketURL(),
		TransitRelayAddress: relayServer.addr,
	}

	c1 := Client{
		RendezvousURL:       rs.WebSocketURL(),
		TransitRelayAddress: relayServer.addr,
	}

	nameplate, rc0, sideID0, err := c0.claimOrAllocateNameplate(ctx, "", false)
	if err != nil {
		t.Fatalf("creator0 claimOrAllocateNameplate: %v", err)
	}

	code := nameplate + "-" + wordlist.ChooseWords(c0.wordCount())
	t.Logf("tunnel code: %s", code)

	_, rc1, sideID1, err := c1.claimOrAllocateNameplate(ctx, code, false)
	if err != nil {
		t.Fatalf("creator1 claimOrAllocateNameplate: %v", err)
	}

	errCh0 := make(chan error, 1)
	errCh1 := make(chan error, 1)

	go func() {
		_, _, err := c0.establishTunnel(ctx, rc0, sideID0, code, false)
		errCh0 <- err
	}()

	go func() {
		_, _, err := c1.establishTunnel(ctx, rc1, sideID1, code, false)
		errCh1 <- err
	}()

	err0 := <-errCh0
	err1 := <-errCh1

	t.Logf("creator0 (sideID=%s): %v", sideID0, err0)
	t.Logf("creator1 (sideID=%s): %v", sideID1, err1)

	var conflictCount, fatalCount int
	for _, err := range []error{err0, err1} {
		if errors.Is(err, ErrTunnelRoleConflict) {
			conflictCount++
		} else if err != nil {
			fatalCount++
		}
	}

	if conflictCount != 1 || fatalCount != 1 {
		t.Fatalf("expected 1 ErrTunnelRoleConflict and 1 fatal error, got %d conflicts and %d fatals", conflictCount, fatalCount)
	}

	winnerSide := "creator0"
	winnerErr := err0
	if errors.Is(err1, ErrTunnelRoleConflict) {
		winnerSide = "creator1"
		winnerErr = err1
	}
	t.Logf("%s wins (gets ErrTunnelRoleConflict for retry)", winnerSide)
	_ = winnerErr
}
