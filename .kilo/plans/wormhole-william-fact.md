# Changelog: tunnel improvements since commit `cad71fc`

## Breaking Changes

### 1. `CreateTunnel` signature changed

```go
// Before (cad71fc):
func (c *Client) CreateTunnel(ctx context.Context) (string, *Tunnel, error)

// After:
func (c *Client) CreateTunnel(ctx context.Context, code string) (string, *Tunnel, error)
```

- `code=""` behaves like old `CreateTunnel()` — allocates a new mailbox, generates `nameplate-word-word` code, returns it
- `code="my-secret"` uses deterministic nameplate generation (HKDF-SHA256 from code), both sides converge on the same nameplate

### 2. `CreateTunnelWithCode` removed

```go
// Before (cad71fc):
func (c *Client) CreateTunnelWithCode(ctx context.Context, code string) (*Tunnel, error)

// After: REMOVED. Use CreateTunnel(ctx, code) instead.
```

The old `CreateTunnelWithCode` returned only `(*Tunnel, error)`. The new `CreateTunnel(ctx, code)` returns `(string, *Tunnel, error)` — the string is the confirmed code (after successful PAKE).

### 3. `JoinTunnel` signature changed

```go
// Before (cad71fc):
func (c *Client) JoinTunnel(ctx context.Context, code string) (*Tunnel, error)

// After:
func (c *Client) JoinTunnel(ctx context.Context, code string) (string, *Tunnel, error)
```

Now returns `(confirmedCode, *Tunnel, error)`. Empty `code` returns an error.

### 4. `Forward` signature changed

```go
// Before (cad71fc):
func (t *Tunnel) Forward(ctx context.Context, localAddr, remoteAddr string) error

// After:
func (t *Tunnel) Forward(ctx context.Context, localAddr string) error
```

The `remoteAddr` parameter was dead code (sent to peer but never used). Removed.

### 5. Tunnel uses dedicated AppID

```go
const TunnelAppID = "abakum.github.io/wormhole/tunnel"
```

Tunnels now use their own AppID instead of `lothar.com/wormhole/text-or-file-xfer`. This means:
- Tunnels are isolated from regular Send/Receive operations (different PAKE identity)
- Tunnel code `4-pharmacy-cleanup` won't accidentally connect to a `SendText` client using the same code
- **Both sides must use the same version** — old `cad71fc` clients and new clients cannot connect (different AppID → PAKE fails)

## New Features

### Deterministic nameplate generation

When `code` is a non-empty secret string, both `CreateTunnel` and `JoinTunnel` derive nameplate candidates deterministically using HKDF-SHA256. Both sides generate the same 5 candidates and try them in order. First free nameplate wins. This avoids the need for `number-words` format codes — any arbitrary secret string works.

### Logging

All tunnel operations now emit `log.Printf` messages with `tunnel:` prefix:
- Rendezvous connection, nameplate allocation/claiming
- PAKE exchange completion (code confirmed)
- Version exchange
- Transit hints (direct/relay counts)
- Connection establishment (direct-tcp or relay)
- Session events (open/close/dial connections)
- Forward/Serve lifecycle

### Graceful shutdown on peer disconnect

`Forward()` and `Serve()` now watch `session.stopCh`. When the peer disconnects, the session closes, `stopCh` signals, and the listener shuts down cleanly instead of hanging.

### Split examples

Old `examples/wormhole-william-tunnel/` (single binary with `-mode serve|forward`) replaced with:
- `examples/wormhole-william-tunnel-serve/` — serve side only
- `examples/wormhole-william-tunnel-forward/` — forward side only

Follows the same pattern as `send-text` / `recv-text` examples.

## Internal Changes

### Extracted `establishTunnel` helper

Shared PAKE + version + transit code (~150 lines) extracted from `CreateTunnel`/`JoinTunnel` into a private `establishTunnel(ctx, rc, sideID, code, isJoiner)` method. The `isJoiner` flag controls whether the function acts as sender (listen → accept) or receiver (connect direct/relay).

### `claimOrAllocateNameplate` rewritten

- `secret=""` → allocate a random nameplate via `CreateMailbox`
- `secret!=""` → try 5 deterministic nameplates, no fallback to allocate (prevents both sides from diverging to different random nameplates)

### Removed dead code

- `nameplateFromCode()` no longer used by tunnel functions
- `_ = nameplate` dead assignments replaced with log messages
- Unused `remoteAddr` parameter removed from `Forward()`

## Migration Guide

```go
// Old (cad71fc):
code, tunnel, err := c.CreateTunnel(ctx)
// or:
tunnel, err := c.CreateTunnelWithCode(ctx, "my-secret")

tunnel, err := c.JoinTunnel(ctx, "4-pharmacy-cleanup")
err := tunnel.Forward(ctx, ":8080", "remote:8080") // remoteAddr was unused

// New:
code, tunnel, err := c.CreateTunnel(ctx, "")       // allocate + generate code
code, tunnel, err := c.CreateTunnel(ctx, "secret") // deterministic nameplates
code, tunnel, err := c.JoinTunnel(ctx, "secret")   // returns confirmed code
err := tunnel.Forward(ctx, ":8080")                 // remoteAddr removed
```
