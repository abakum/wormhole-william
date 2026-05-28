package wormhole

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"strconv"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wormhole/tunnel"
	"github.com/psanford/wormhole-william/wordlist"
	"crypto/sha256"
	"golang.org/x/crypto/hkdf"
)

const TunnelAppID = "abakum.github.io/wormhole/tunnel"

func (c *Client) tunnelAppID() string {
	return TunnelAppID
}

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
			directCount, relayCount := countTransitHints(gm.Transit)
			log.Printf("tunnel: received peer transit hints (%d direct, %d relay)", directCount, relayCount)
			return gm.Transit, nil
		}
		if gm.Error != nil {
			return nil, fmt.Errorf("peer error: %s", *gm.Error)
		}
	}
}

var ErrTunnelRoleConflict = errors.New("tunnel: both sides are creators")

func readRoleMsg(ch <-chan rendezvous.MailboxEvent, sharedKey []byte) (string, string, error) {
	for {
		msg, ok := <-ch
		if !ok {
			return "", "", errors.New("channel closed waiting for role")
		}
		if msg.Error != nil {
			return "", "", msg.Error
		}
		if _, err := strconv.Atoi(msg.Phase); err != nil {
			continue
		}
		var gm genericMessage
		if err := openAndUnmarshal(&gm, msg, sharedKey); err != nil {
			continue
		}
		if gm.Offer != nil && gm.Offer.Message != nil {
			return *gm.Offer.Message, msg.Side, nil
		}
		if gm.Error != nil {
			return "", "", fmt.Errorf("peer error: %s", *gm.Error)
		}
	}
}

func countTransitHints(t *transitMsg) (direct, relay int) {
	for _, h := range t.HintsV1 {
		switch h.Type {
		case "direct-tcp-v1":
			direct++
		case "relay-v1":
			relay++
		}
	}
	return
}

func deterministicNameplates(secret string, count int) []string {
	candidates := make([]string, count)
	for i := 0; i < count; i++ {
		digits := i + 1
		min := int(math.Pow10(digits - 1))
		max := int(math.Pow10(digits)) - 1

		purpose := fmt.Sprintf("wormhole:tunnel:nameplate-%d", i)
		h := hkdf.New(sha256.New, []byte(secret), nil, []byte(purpose))
		buf := make([]byte, 4)
		io.ReadFull(h, buf)

		n := min + int(binary.BigEndian.Uint32(buf)%uint32(max-min+1))
		candidates[i] = strconv.Itoa(n)
	}
	return candidates
}

func (c *Client) claimOrAllocateNameplate(ctx context.Context, secret string, isJoiner bool) (string, *rendezvous.Client, string, error) {
	appID := c.tunnelAppID()

	if secret == "" {
		sideID := crypto.RandSideID()
		rc := rendezvous.NewClient(c.url(), sideID, appID)
		if _, err := rc.Connect(ctx); err != nil {
			return "", nil, "", err
		}
		nameplate, err := rc.CreateMailbox(ctx)
		if err != nil {
			return "", nil, "", err
		}
		log.Printf("tunnel: allocated nameplate %s", nameplate)
		return nameplate, rc, sideID, nil
	}

	if nameplate, err := nameplateFromCode(secret); err == nil {
		sideID := crypto.RandSideID()
		rc := rendezvous.NewClient(c.url(), sideID, appID)
		if _, err := rc.Connect(ctx); err != nil {
			return "", nil, "", err
		}
		if err := rc.AttachMailbox(ctx, nameplate); err != nil {
			rc.Close(ctx, rendezvous.Errory)
			return "", nil, "", fmt.Errorf("attach mailbox %s: %w", nameplate, err)
		}
		log.Printf("tunnel: claimed nameplate %s from code", nameplate)
		return nameplate, rc, sideID, nil
	}

	candidates := deterministicNameplates(secret, 5)
	for _, nameplate := range candidates {
		sideID := crypto.RandSideID()
		rc := rendezvous.NewClient(c.url(), sideID, appID)
		if _, err := rc.Connect(ctx); err != nil {
			log.Printf("tunnel: connect failed for nameplate %s: %v", nameplate, err)
			continue
		}
		if err := rc.AttachMailbox(ctx, nameplate); err != nil {
			log.Printf("tunnel: nameplate %s busy (%v), trying next", nameplate, err)
			rc.Close(ctx, rendezvous.Errory)
			continue
		}
		log.Printf("tunnel: claimed deterministic nameplate %s", nameplate)
		return nameplate, rc, sideID, nil
	}

	if isJoiner {
		return "", nil, "", fmt.Errorf("all %d deterministic nameplates busy, try a different secret", len(candidates))
	}

	sideID := crypto.RandSideID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)
	if _, err := rc.Connect(ctx); err != nil {
		return "", nil, "", err
	}
	nameplate, err := rc.CreateMailbox(ctx)
	if err != nil {
		return "", nil, "", err
	}
	log.Printf("tunnel: all deterministic nameplates busy, allocated fallback nameplate %s", nameplate)
	return nameplate, rc, sideID, nil
}

func (c *Client) establishTunnel(ctx context.Context, rc *rendezvous.Client, sideID, code string, isJoiner bool) (string, *tunnel.Tunnel, error) {
	appID := c.tunnelAppID()

	var returnErr error
	defer func() {
		if returnErr != nil {
			rc.Close(ctx, rendezvous.Errory)
		}
	}()

	cp := newClientProtocol(ctx, rc, sideID, appID)

	if err := cp.WritePake(ctx, code); err != nil {
		returnErr = err
		return "", nil, err
	}
	if err := cp.ReadPake(ctx); err != nil {
		returnErr = err
		return "", nil, err
	}
	log.Printf("tunnel: PAKE exchange complete (code confirmed)")

	if err := cp.WriteVersion(ctx); err != nil {
		returnErr = err
		return "", nil, err
	}
	if _, err := cp.ReadVersion(); err != nil {
		returnErr = err
		return "", nil, err
	}
	log.Printf("tunnel: version exchange complete")

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

	role := "creator"
	if isJoiner {
		role = "joiner"
	}
	if err := cp.WriteAppData(ctx, &genericMessage{Offer: &offerMsg{Message: &role}}); err != nil {
		returnErr = err
		return "", nil, err
	}
	peerRole, peerSideID, err := readRoleMsg(cp.ch, cp.sharedKey)
	if err != nil {
		returnErr = err
		return "", nil, err
	}
	log.Printf("tunnel: role exchange complete (us=%s peer=%s)", role, peerRole)

	if role == "creator" && peerRole == "creator" {
		if sideID > peerSideID {
			errStr := "tunnel: both sides are creators, backing off"
			cp.WriteAppData(ctx, &genericMessage{Error: &errStr})
			returnErr = fmt.Errorf("tunnel: both sides are creators, giving up")
			return "", nil, returnErr
		}
		log.Printf("tunnel: both creators, peer will back off, retrying")
		returnErr = ErrTunnelRoleConflict
		return "", nil, returnErr
	}

	transitKey := deriveTransitKey(cp.sharedKey, appID)
	transport := newFileTransport(transitKey, appID, c.relayAddr())

	if isJoiner {
		log.Printf("tunnel: waiting for peer transit hints...")
		peerTransit, err := waitForTransitMsg(cp.ch, cp.sharedKey)
		if err != nil {
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

		log.Printf("tunnel: trying direct connection to peer...")
		conn, err := transport.connectDirect(peerTransit)
		if err != nil {
			returnErr = err
			return "", nil, err
		}

		if conn != nil {
			log.Printf("tunnel: transit connection established via direct-tcp from %s", conn.RemoteAddr())
		} else {
			log.Printf("tunnel: direct connection failed, trying relay...")
			conn, err = transport.connectViaRelay(peerTransit)
			if err != nil {
				returnErr = err
				return "", nil, err
			}
			if conn != nil {
				log.Printf("tunnel: transit connection established via relay from %s", conn.RemoteAddr())
			}
		}

		if conn == nil {
			returnErr = errors.New("failed to establish transit connection (both direct and relay failed)")
			return "", nil, returnErr
		}

		cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")
		session := tunnel.NewSession(&cryptorAdapter{cryptor})

		rc.Close(ctx, rendezvous.Happy)

		return code, tunnel.NewTunnel(session), nil
	}

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

	directCount, relayCount := countTransitHints(transitMsg)
	log.Printf("tunnel: transit listening (direct hints=%d, relay hints=%d, relay addr=%s)", directCount, relayCount, c.relayAddr())

	if err := cp.WriteAppData(ctx, &genericMessage{Transit: transitMsg}); err != nil {
		returnErr = err
		return "", nil, err
	}

	_, err = waitForTransitMsg(cp.ch, cp.sharedKey)
	if err != nil {
		returnErr = err
		return "", nil, err
	}

	log.Printf("tunnel: waiting for incoming transit connection...")
	conn, err := transport.acceptConnection(ctx)
	if err != nil {
		returnErr = err
		return "", nil, err
	}

	log.Printf("tunnel: transit connection established from %s", conn.RemoteAddr())

	cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")
	session := tunnel.NewSession(&cryptorAdapter{cryptor})

	rc.Close(ctx, rendezvous.Happy)

	return code, tunnel.NewTunnel(session), nil
}

func (c *Client) CreateTunnel(ctx context.Context, code string) (string, *tunnel.Tunnel, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	log.Printf("tunnel: connecting to rendezvous %s", c.url())

	generatedCode := ""
	const maxRoleConflictRetries = 3
	for attempt := 0; ; attempt++ {
		nameplate, rc, sideID, err := c.claimOrAllocateNameplate(ctx, code, false)
		if err != nil {
			return "", nil, fmt.Errorf("claim nameplate: %w", err)
		}

		tunnelCode := code
		if tunnelCode == "" {
			if generatedCode == "" {
				generatedCode = nameplate + "-" + wordlist.ChooseWords(c.wordCount())
			}
			tunnelCode = generatedCode
			log.Printf("tunnel: created mailbox, code=%q", tunnelCode)
		} else {
			log.Printf("tunnel: claimed nameplate %s for code", nameplate)
		}

		result, t, err := c.establishTunnel(ctx, rc, sideID, tunnelCode, false)
		if err != nil {
			if errors.Is(err, ErrTunnelRoleConflict) && attempt < maxRoleConflictRetries {
				log.Printf("tunnel: role conflict, retrying (%d/%d)...", attempt+1, maxRoleConflictRetries)
				continue
			}
			return "", nil, err
		}
		return result, t, nil
	}
}

func (c *Client) JoinTunnel(ctx context.Context, code string) (string, *tunnel.Tunnel, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	if code == "" {
		return "", nil, errors.New("join tunnel: code is required")
	}

	log.Printf("tunnel: connecting to rendezvous %s", c.url())

	nameplate, rc, sideID, err := c.claimOrAllocateNameplate(ctx, code, true)
	if err != nil {
		return "", nil, fmt.Errorf("claim nameplate: %w", err)
	}

	log.Printf("tunnel: claimed nameplate %s for code", nameplate)

	return c.establishTunnel(ctx, rc, sideID, code, true)
}
