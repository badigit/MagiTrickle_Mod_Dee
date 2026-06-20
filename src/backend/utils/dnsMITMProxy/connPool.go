package dnsMITMProxy

import (
	"context"
	"errors"
	"net"
	"sync"
)

// connPool is a simple connection pool based on a channel
type connPool struct {
	network string
	addr    string
	pool    chan net.Conn
	maxIdle uint
	mu      sync.Mutex
	closed  bool
}

func newConnPool(network, addr string, maxIdle uint) *connPool {
	return &connPool{
		network: network,
		addr:    addr,
		pool:    make(chan net.Conn, maxIdle),
		maxIdle: maxIdle,
	}
}

func (p *connPool) Get(ctx context.Context) (net.Conn, error) {
	// Check context before trying to get/create connection
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// The non-blocking receive runs under the same lock as Close(), so the
	// channel is never read after Close() has closed and drained it. The
	// receive has a default branch, so holding the lock cannot block.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("pool is closed")
	}
	select {
	case conn := <-p.pool:
		p.mu.Unlock()
		return conn, nil
	default:
		p.mu.Unlock()
	}

	// Dial outside the lock — never hold a mutex across I/O.
	var d net.Dialer
	return d.DialContext(ctx, p.network, p.addr)
}

func (p *connPool) Put(conn net.Conn) {
	// The non-blocking send runs under the same lock as Close(): Close() also
	// holds the lock while it sets p.closed and closes the channel, so we can
	// never send on an already-closed channel here. The send has a default
	// branch, so holding the lock cannot block.
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return
	}
	select {
	case p.pool <- conn:
		p.mu.Unlock()
	default:
		p.mu.Unlock()
		_ = conn.Close()
	}
}

func (p *connPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	// Close and drain under the lock: Get()/Put() serialise on the same lock
	// and bail out once p.closed is set, so no goroutine can touch the channel
	// concurrently with the close below.
	close(p.pool)
	for conn := range p.pool {
		_ = conn.Close()
	}
}
