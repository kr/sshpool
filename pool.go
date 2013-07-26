package sshpool

import (
	"code.google.com/p/go.crypto/ssh"
	"log"
	"strconv"
	"sync"
	"time"
)

// Open opens a new SSH session on the given server using DefaultPool.
func Open(net, addr string, config *ssh.ClientConfig) (*ssh.Session, error) {
	return DefaultPool.Open(net, addr, config)
}

type Pool struct {
	// If nil, ssh.Dial is used.
	Dial func(net, addr string, config *ssh.ClientConfig) (*ssh.ClientConn, error)

	// Computes a key to distinguish ssh connections.
	// If nil, AddrUserKey is used.
	Key func(net, addr string, config *ssh.ClientConfig) string

	tab map[string]*conn
	mu  sync.Mutex
}

var DefaultPool = new(Pool)

// Open starts a new SSH session on the given server, reusing
// an existing connection if possible. If no connection exists,
// or if opening the session fails, Open attempts to dial a new
// connection. If dialing fails, Open returns the error from Dial.
func (p *Pool) Open(net, addr string, config *ssh.ClientConfig) (*ssh.Session, error) {
	k := p.key(net, addr, config)
	for {
		c := p.getConn(k, net, addr, config)
		if c.err != nil {
			p.removeConn(k, c)
			return nil, c.err
		}
		sessionCh := make(chan interface{})
		go func() {
			if s, err := c.c.NewSession(); err == nil {
				select {
				case sessionCh <- s:
				}
			} else {
				select {
				case sessionCh <- err:
				}
			}
		}()
		select {
		case response := <-sessionCh:
			switch resp := response.(type) {
			case *ssh.Session:
				return resp, nil
			case error:
				log.Print("sshpool: failed to establish new session: %v", resp)
				// try again (see below)
			default:
				panic("sshpool: unexpected type on channel: %v", resp)
			}
		case <-time.After(2 * time.Second):
			// give up; toss the connection and try again
		}
		p.removeConn(k, c)
		c.c.Close()
	}
}

type conn struct {
	c   *ssh.ClientConn
	wg  sync.WaitGroup
	err error
}

// getConn gets an ssh connection from the pool for key.
// If none is available, it dials anew.
func (p *Pool) getConn(k, net, addr string, config *ssh.ClientConfig) *conn {
	p.mu.Lock()
	if p.tab == nil {
		p.tab = make(map[string]*conn)
	}
	c, ok := p.tab[k]
	if ok {
		p.mu.Unlock()
		c.wg.Wait()
		return c
	}
	c = new(conn)
	p.tab[k] = c
	c.wg.Add(1)
	p.mu.Unlock()
	c.c, c.err = p.dial(net, addr, config)
	c.wg.Done()
	return c
}

// removeConn removes c1 from the pool if present.
func (p *Pool) removeConn(k string, c1 *conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.tab[k]
	if ok && c == c1 {
		delete(p.tab, k)
	}
}

func (p *Pool) dial(net, addr string, config *ssh.ClientConfig) (*ssh.ClientConn, error) {
	dial := p.Dial
	if dial == nil {
		dial = ssh.Dial
	}
	return dial(net, addr, config)
}

func (p *Pool) key(net, addr string, config *ssh.ClientConfig) string {
	key := p.Key
	if key == nil {
		key = AddrUserKey
	}
	return key(net, addr, config)
}

// Returns a distinct string for any unique combination of net,
// addr, and config.User.
func AddrUserKey(net, addr string, config *ssh.ClientConfig) string {
	return strconv.Quote(net) + " " + strconv.Quote(addr) + " " + strconv.Quote(config.User)
}
