# Plan: Wormhole Tunnel for wormhole-william

## Цель

Добавить в форк wormhole-william возможность туннелирования TCP-соединений через wormhole-канал — аналог croc-туннеля из проекта crocson. Выбор между croc и wormhole для проброса TCP (WebDAV, чат, и т.д.).

## Ограничения

- **Штатные серверы**: mailbox + transit relay (relay.magic-wormhole.io и аналоги)
- **Только crocson ↔ crocson**: совместимость с Python magic-wormhole не нужна
- **Не ломать существующий код**: только добавлять новые файлы, не модифицировать существующие

## Принцип: "Не ломать transportCryptor"

Существующие `transportCryptor`, `file_transport`, `send.go`, `recv.go` — не трогаем. Вместо этого:

1. Новый файл `wormhole/tunnel.go` в том же пакете `wormhole` — имеет доступ к неэкспортируемым типам (`clientProtocol`, `transportCryptor`, `deriveTransitKey`, etc.) без их изменения
2. Новый подпакет `wormhole/tunnel/` — самостоятельный, отвечает только за мультиплексирование и TCP-форвардинг

## Архитектура

```
wormhole/
  tunnel.go (НОВЫЙ — в пакете wormhole)
    ├── CreateTunnel() — PAKE + mailbox + transit → tunnel.Session
    └── JoinTunnel()   — PAKE + mailbox + transit → tunnel.Session
                         использует: clientProtocol, transportCryptor,
                         deriveTransitKey, fileTransport (без изменений)

  tunnel/
    protocol.go (НОВЫЙ)
      └── Сообщения туннеля: OPEN / DATA / CLOSE (encode/decode)

    session.go (НОВЫЙ)
      └── Session: мультиплексирование + маршрутизация connID
      └── tunnelConn: net.Conn через туннель

    tunnel.go (НОВЫЙ)
      └── Публичный API: Forward(), Dial(), Listen(), Close()
```

### Поток данных

```
Отправитель                         Relay/Direct                 Получатель
    │                                    │                           │
    │  clientProtocol.WritePake          │                           │
    │  clientProtocol.ReadPake           │                           │
    │  clientProtocol.WriteVersion       │                           │
    │  clientProtocol.ReadVersion        │                           │
    │                                    │                           │
    │  WriteAppData({tunnel:true})       │                           │
    │  ReadAppData({tunnel_ack:"ok"})    │                           │
    │  Exchange transit hints            │                           │
    │                                    │                           │
    │  fileTransport: direct/relay TCP   │                           │
    │  transportCryptor: NaCl secretbox  │                           │
    │                                    │                           │
    │  tunnel.Session (мультиплексор):   │                           │
    │  ─── OPEN(connID, addr) ────────>  │  ─── OPEN ────────────>  │
    │                                    │                     dial local
    │  <── DATA(connID, payload) ──────  │  <── DATA ────────────  │
    │  ─── CLOSE(connID) ─────────────>  │  ─── CLOSE ──────────>  │
```

## Файлы

### `wormhole/tunnel.go` — Интеграция (в пакете wormhole)

Новый файл в пакете `wormhole`, добавляет методы к `Client`. Не трогает существующие файлы.

```go
package wormhole

// CreateTunnel создаёт wormhole-туннель, возвращает код для получателя
func (c *Client) CreateTunnel(ctx context.Context) (string, *tunnel.Tunnel, error) {
    // 1. rendezvous.NewClient + Connect
    // 2. clientProtocol.WritePake / ReadPake
    // 3. clientProtocol.WriteVersion / ReadVersion
    // 4. clientProtocol.WriteAppData({tunnel: true})
    // 5. clientProtocol.Collect(collectTunnelAck)
    // 6. deriveTransitKey(sharedKey, appID)
    // 7. newFileTransport + listen + listenRelay
    // 8. exchange transit hints
    // 9. acceptConnection / connectDirect / connectViaRelay
    // 10. newTransportCryptor(conn, transitKey, ...)
    // 11. tunnel.NewSession(cryptor, isSender=true)
    // 12. tunnel.NewTunnel(session)
}
```

Типы сообщений:
```go
type tunnelOfferMsg struct {
    Tunnel *struct{} `json:"tunnel,omitempty"`
}

type tunnelAckMsg struct {
    TunnelAck string `json:"tunnel_ack,omitempty"`
}
```

Новый collectType: `collectTunnelAck`

### `wormhole/tunnel/protocol.go` — Протокол мультиплексирования

Формат сообщений поверх расшифрованных transit-records:

```
[1 byte:  message type]
[8 bytes: connID (big-endian)]
[4 bytes: payload length (big-endian)]
[N bytes: payload]

Message types:
  0x01 OPEN  — payload = адрес (UTF-8 "host:port")
  0x02 DATA  — payload = данные TCP-соединения
  0x03 CLOSE — payload пустой
```

Функции:
- `encodeOpen(connID uint64, addr string) []byte`
- `encodeData(connID uint64, data []byte) []byte`
- `encodeClose(connID uint64) []byte`
- `decode(msg []byte) (msgType byte, connID uint64, payload []byte, error)`

### `wormhole/tunnel/session.go` — Сессия мультиплексирования

```go
type RecordReader interface {
    ReadRecord() ([]byte, error)
}

type RecordWriter interface {
    WriteRecord(msg []byte) error
    Close() error
}

type Session struct {
    rw       RecordReaderWriter  // transportCryptor (через интерфейс)
    conns    sync.Map            // connID → *tunnelConn
    nextID   uint64
    isServer bool                // true = принимает OPEN, false = отправляет OPEN
    stopCh   chan struct{}
    wg       sync.WaitGroup
}

// tunnelConn реализует net.Conn через туннель
type tunnelConn struct {
    session  *Session
    connID   uint64
    readBuf  bytes.Buffer
    readCh   chan []byte
    closeCh  chan struct{}
    once     sync.Once
    local    net.Conn
}
```

Session:
- `readLoop()` — читает records из cryptor, маршрутизирует по connID
- При получении OPEN (server-side): dial локальный адрес, создать tunnelConn, проксировать
- При получении DATA: доставить в соответствующий tunnelConn
- При получении CLOSE: закрыть tunnelConn
- `openConn(addr string) (*tunnelConn, error)` — отправить OPEN, ждать данных
- `closeConn(connID uint64)` — отправить CLOSE

tunnelConn:
- `Read(p []byte)` — читать из readCh
- `Write(p []byte)` — отправить DATA через session
- `Close()` — отправить CLOSE через session

Ключевой момент: Session работает через интерфейс `RecordReader/RecordWriter`, а не напрямую с `transportCryptor`. Это развязывает пакет tunnel от внутренностей пакета wormhole.

### `wormhole/tunnel/tunnel.go` — Публичный API

```go
type Tunnel struct {
    session *Session
}

// Forward пробрасывает TCP: слушает localAddr, каждое соединение
// маршрутизирует через туннель к remoteAddr на другой стороне
func (t *Tunnel) Forward(ctx context.Context, localAddr, remoteAddr string) error

// Dial открывает net.Conn через туннель к remoteAddr
func (t *Tunnel) Dial(ctx context.Context, remoteAddr string) (net.Conn, error)

// Listen возвращает net.Listener — принимает соединения из туннеля
func (t *Tunnel) Listen() net.Listener

// Close закрывает туннель и все соединения
func (t *Tunnel) Close() error

// Ready сигнализирует что туннель установлен
func (t *Tunnel) Ready() <-chan struct{}
```

Forward — основная функция для crocson:
```go
// На стороне получателя (открывает доступ к WebDAV отправителя):
tunnel.Forward(ctx, "localhost:8080", "localhost:8080")

// Это:
// 1. Слушает localhost:8080
// 2. Каждое входящее TCP-соединение → отправляет OPEN(remoteAddr) через туннель
// 3. Отправитель получает OPEN → dial localhost:8080 (свой WebDAV)
// 4. Данные проксируются двунаправленно
```

## Порядок реализации

### Шаг 1: `wormhole/tunnel/protocol.go`
- Типы сообщений OPEN/DATA/CLOSE
- Encode/decode функции
- ~80 строк

### Шаг 2: `wormhole/tunnel/session.go`
- RecordReader/RecordWriter интерфейсы
- Session: readLoop, маршрутизация, lifecycle
- tunnelConn: net.Conn через туннель
- Проксирование: local TCP ↔ tunnel DATA
- ~350 строк

### Шаг 3: `wormhole/tunnel/tunnel.go`
- Tunnel: Forward, Dial, Listen, Close
- Обёртка над Session
- ~120 строк

### Шаг 4: `wormhole/tunnel.go`
- Client.CreateTunnel / Client.JoinTunnel
- tunnelOffer/tunnelAck типы
- Полный flow: PAKE → transit → tunnel.Session
- ~250 строк

### Шаг 5: Тесты
- `wormhole/tunnel/protocol_test.go` — encode/decode
- `wormhole/tunnel/session_test.go` — мультиплексирование через net.Pipe
- Integration: loopback tunnel через localhost

## Итого

- **4 новых файла**, **0 изменённых файлов**
- ~800 строк нового кода
- Не ломает SendText/SendFile/SendDirectory/Receive
- Работает со штатными wormhole-серверами
- Только crocson ↔ crocson
