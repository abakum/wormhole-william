package wormhole

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wormhole/tunnel"
	"github.com/psanford/wormhole-william/wordlist"
)

type cryptorAdapter struct {
	c *transportCryptor
}

func (a *cryptorAdapter) ReadRecord() ([]byte, error)  { return a.c.readRecord() }
func (a *cryptorAdapter) WriteRecord(msg []byte) error { return a.c.writeRecord(msg) }
func (a *cryptorAdapter) Close() error                 { return a.c.Close() }

func waitForTransitMsg(ch <-chan rendezvous.MailboxEvent, sharedKey []byte) (*transitMsg, error) {
	for {
		msg, ok := <-ch
		if !ok {
			return nil, errors.New("channel closed waiting for transit message")
		}
		if msg.Error != nil {
			return nil, msg.Error
		}
		if _, err := strconv.Atoi(msg.Phase); err != nil {
			continue
		}
		var gm genericMessage
		if err := openAndUnmarshal(&gm, msg, sharedKey); err != nil {
			continue
		}
		if gm.Transit != nil {
			return gm.Transit, nil
		}
		if gm.Error != nil {
			return nil, fmt.Errorf("peer error: %s", *gm.Error)
		}
	}
}

func (c *Client) CreateTunnel(ctx context.Context) (string, *tunnel.Tunnel, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err := rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	nameplate, err := rc.CreateMailbox(ctx)
	if err != nil {
		return "", nil, err
	}

	code := nameplate + "-" + wordlist.ChooseWords(c.wordCount())

	cp := newClientProtocol(ctx, rc, sideID, appID)

	var returnErr error
	defer func() {
		if returnErr != nil {
			rc.Close(ctx, rendezvous.Errory)
		}
	}()

	if err := cp.WritePake(ctx, code); err != nil {
		returnErr = err
		return "", nil, err
	}
	if err := cp.ReadPake(ctx); err != nil {
		returnErr = err
		return "", nil, err
	}
	if err := cp.WriteVersion(ctx); err != nil {
		returnErr = err
		return "", nil, err
	}
	if _, err := cp.ReadVersion(); err != nil {
		returnErr = err
		return "", nil, err
	}

	if c.VerifierOk != nil {
		verifier, err := cp.Verifier()
		if err != nil {
			returnErr = err
			return "", nil, err
		}
		if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
			returnErr = errors.New("tunnel rejected by verification check")
			return "", nil, returnErr
		}
	}

	transitKey := deriveTransitKey(cp.sharedKey, appID)
	transport := newFileTransport(transitKey, appID, c.relayAddr())

	if err := transport.listen(); err != nil {
		returnErr = err
		return "", nil, err
	}
	if err := transport.listenRelay(); err != nil {
		returnErr = err
		return "", nil, err
	}

	transitMsg, err := transport.makeTransitMsg()
	if err != nil {
		returnErr = fmt.Errorf("make transit msg error: %s", err)
		return "", nil, err
	}

	if err := cp.WriteAppData(ctx, &genericMessage{Transit: transitMsg}); err != nil {
		returnErr = err
		return "", nil, err
	}

	_, err = waitForTransitMsg(cp.ch, cp.sharedKey)
	if err != nil {
		returnErr = err
		return "", nil, err
	}

	conn, err := transport.acceptConnection(ctx)
	if err != nil {
		returnErr = err
		return "", nil, err
	}

	cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")
	session := tunnel.NewSession(&cryptorAdapter{cryptor})

	rc.Close(ctx, rendezvous.Happy)

	return code, tunnel.NewTunnel(session), nil
}

func (c *Client) CreateTunnelWithCode(ctx context.Context, code string) (*tunnel.Tunnel, error) {
	if err := c.validateRelayAddr(); err != nil {
		return nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	nameplate, err := nameplateFromCode(code)
	if err != nil {
		return nil, fmt.Errorf("invalid code for tunnel: %w", err)
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	var returnErr error
	defer func() {
		if returnErr != nil {
			rc.Close(ctx, rendezvous.Errory)
		}
	}()

	_, err = rc.Connect(ctx)
	if err != nil {
		returnErr = err
		return nil, err
	}

	if err := rc.AttachMailbox(ctx, nameplate); err != nil {
		returnErr = err
		return nil, err
	}

	cp := newClientProtocol(ctx, rc, sideID, appID)

	if err := cp.WritePake(ctx, code); err != nil {
		returnErr = err
		return nil, err
	}
	if err := cp.ReadPake(ctx); err != nil {
		returnErr = err
		return nil, err
	}
	if err := cp.WriteVersion(ctx); err != nil {
		returnErr = err
		return nil, err
	}
	if _, err := cp.ReadVersion(); err != nil {
		returnErr = err
		return nil, err
	}

	if c.VerifierOk != nil {
		verifier, err := cp.Verifier()
		if err != nil {
			returnErr = err
			return nil, err
		}
		if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
			returnErr = errors.New("tunnel rejected by verification check")
			return nil, returnErr
		}
	}

	transitKey := deriveTransitKey(cp.sharedKey, appID)
	transport := newFileTransport(transitKey, appID, c.relayAddr())

	if err := transport.listen(); err != nil {
		returnErr = err
		return nil, err
	}
	if err := transport.listenRelay(); err != nil {
		returnErr = err
		return nil, err
	}

	transitMsg, err := transport.makeTransitMsg()
	if err != nil {
		returnErr = fmt.Errorf("make transit msg error: %s", err)
		return nil, err
	}

	if err := cp.WriteAppData(ctx, &genericMessage{Transit: transitMsg}); err != nil {
		returnErr = err
		return nil, err
	}

	_, err = waitForTransitMsg(cp.ch, cp.sharedKey)
	if err != nil {
		returnErr = err
		return nil, err
	}

	conn, err := transport.acceptConnection(ctx)
	if err != nil {
		returnErr = err
		return nil, err
	}

	cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")
	session := tunnel.NewSession(&cryptorAdapter{cryptor})

	rc.Close(ctx, rendezvous.Happy)

	return tunnel.NewTunnel(session), nil
}

func (c *Client) JoinTunnel(ctx context.Context, code string) (*tunnel.Tunnel, error) {
	if err := c.validateRelayAddr(); err != nil {
		return nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	var returnErr error
	defer func() {
		if returnErr != nil {
			rc.Close(ctx, rendezvous.Errory)
		}
	}()

	_, err := rc.Connect(ctx)
	if err != nil {
		returnErr = err
		return nil, err
	}

	nameplate, err := nameplateFromCode(code)
	if err != nil {
		returnErr = err
		return nil, err
	}

	if err := rc.AttachMailbox(ctx, nameplate); err != nil {
		returnErr = err
		return nil, err
	}

	cp := newClientProtocol(ctx, rc, sideID, appID)

	if err := cp.WritePake(ctx, code); err != nil {
		returnErr = err
		return nil, err
	}
	if err := cp.ReadPake(ctx); err != nil {
		returnErr = err
		return nil, err
	}
	if err := cp.WriteVersion(ctx); err != nil {
		returnErr = err
		return nil, err
	}
	if _, err := cp.ReadVersion(); err != nil {
		returnErr = err
		return nil, err
	}

	if c.VerifierOk != nil {
		verifier, err := cp.Verifier()
		if err != nil {
			returnErr = err
			return nil, err
		}
		if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
			returnErr = errors.New("tunnel rejected by verification check")
			return nil, returnErr
		}
	}

	peerTransit, err := waitForTransitMsg(cp.ch, cp.sharedKey)
	if err != nil {
		returnErr = err
		return nil, err
	}

	transitKey := deriveTransitKey(cp.sharedKey, appID)
	transport := newFileTransport(transitKey, appID, c.relayAddr())

	transitMsg, err := transport.makeTransitMsg()
	if err != nil {
		returnErr = fmt.Errorf("make transit msg error: %s", err)
		return nil, err
	}

	if err := cp.WriteAppData(ctx, &genericMessage{Transit: transitMsg}); err != nil {
		returnErr = err
		return nil, err
	}

	conn, err := transport.connectDirect(peerTransit)
	if err != nil {
		returnErr = err
		return nil, err
	}

	if conn == nil {
		conn, err = transport.connectViaRelay(peerTransit)
		if err != nil {
			returnErr = err
			return nil, err
		}
	}

	if conn == nil {
		returnErr = errors.New("failed to establish transit connection")
		return nil, returnErr
	}

	cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")
	session := tunnel.NewSession(&cryptorAdapter{cryptor})

	rc.Close(ctx, rendezvous.Happy)

	return tunnel.NewTunnel(session), nil
}
