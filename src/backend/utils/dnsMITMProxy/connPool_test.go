package dnsMITMProxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fake upstream DNS server that closes idle connections after idleTimeout.
// This simulates real DNS server behavior (RFC 7766 recommends closing idle TCP).
func startFakeUpstream(t *testing.T, idleTimeout time.Duration) (addr string, stop func()) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Each connection: read something, reply, then close after idle timeout
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					c.SetReadDeadline(time.Now().Add(idleTimeout))
					n, err := c.Read(buf)
					if err != nil {
						// Idle timeout expired or connection closed — close from server side.
						// This is exactly what real upstream DNS does.
						return
					}
					// Echo back as "response"
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() {
		close(done)
		listener.Close()
	}
}

func TestBrokenPipe_PoolReusesDeadConnection(t *testing.T) {
	// Upstream closes idle connections after 100ms
	addr, stop := startFakeUpstream(t, 100*time.Millisecond)
	defer stop()

	pool := newConnPool("tcp", addr, 5)
	defer pool.Close()

	ctx := context.Background()

	// --- Step 1: normal request, works fine ---
	conn, err := pool.Get(ctx)
	if err != nil {
		t.Fatal("Get:", err)
	}

	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal("Write #1:", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal("Read #1:", err)
	}
	t.Logf("Step 1 OK: sent 'hello', got '%s'", string(buf[:n]))

	// Return to pool (this is what the production code does)
	pool.Put(conn)

	// --- Step 2: wait for upstream to close the connection ---
	t.Log("Step 2: waiting 300ms for upstream to close idle connection...")
	time.Sleep(300 * time.Millisecond)

	// --- Step 3: get connection from pool — it's the SAME dead connection ---
	conn2, err := pool.Get(ctx)
	if err != nil {
		t.Fatal("Get #2:", err)
	}

	// Try to write — this is where broken pipe happens
	_, err = conn2.Write([]byte("world"))

	if err != nil {
		// SUCCESS: we reproduced the bug!
		if strings.Contains(err.Error(), "broken pipe") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "forcibly closed") ||
			strings.Contains(err.Error(), "EOF") {
			t.Logf("Step 3: REPRODUCED! Write to stale connection failed: %v", err)
		} else {
			t.Logf("Step 3: Write failed with unexpected error: %v", err)
		}
	} else {
		// On some OS the first Write after FIN may succeed (data buffered in kernel),
		// but the Read will fail because upstream already closed.
		_, err = conn2.Read(buf)
		if err != nil {
			t.Logf("Step 3: REPRODUCED! Write succeeded but Read failed: %v", err)
		} else {
			t.Log("Step 3: both Write and Read succeeded — could not reproduce on this OS/timing")
		}
	}
	conn2.Close()
}

// TestConnPool_ConcurrentCloseNoPanic воспроизводит гонку Close vs Get/Put.
// До фикса Put мог выполнить `p.pool <- conn` уже после того, как Close сделал
// close(p.pool) → паника "send on closed channel"; Get мог прочитать zero-value
// из закрытого канала и вернуть (nil, nil). С сериализацией канальных операций
// под общим мьютексом ни того, ни другого произойти не может. Запускать с -race.
func TestConnPool_ConcurrentCloseNoPanic(t *testing.T) {
	addr, stop := startFakeUpstream(t, time.Second)
	defer stop()

	pool := newConnPool("tcp", addr, 8)

	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic in worker (Close/Put race not fixed): %v", r)
				}
			}()
			<-start
			for j := 0; j < 300; j++ {
				conn, err := pool.Get(context.Background())
				if err != nil {
					return // пул закрыт — корректный путь, не паника
				}
				if conn == nil {
					t.Errorf("Get returned (nil, nil) — closed-channel read leaked through")
					return
				}
				pool.Put(conn)
			}
		}()
	}

	close(start)
	time.Sleep(2 * time.Millisecond) // дать воркерам войти в горячий цикл
	pool.Close()                     // закрываем посреди полёта
	wg.Wait()
}

func TestNoBrokenPipe_NewConnectionEveryTime(t *testing.T) {
	// Same upstream with 100ms idle timeout
	addr, stop := startFakeUpstream(t, 100*time.Millisecond)
	defer stop()

	ctx := context.Background()

	for i := 0; i < 3; i++ {
		// Wait longer than idle timeout
		if i > 0 {
			time.Sleep(300 * time.Millisecond)
		}

		// Always create new connection (our fix)
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatal("Dial:", err)
		}

		_, err = conn.Write([]byte(fmt.Sprintf("request-%d", i)))
		if err != nil {
			t.Fatalf("Request %d: Write failed: %v (should NOT happen with fresh connections)", i, err)
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Request %d: Read failed: %v", i, err)
		}
		t.Logf("Request %d OK: got '%s'", i, string(buf[:n]))

		conn.Close() // close immediately, not pooled
	}
	t.Log("All requests succeeded — no broken pipe with fresh connections")
}
