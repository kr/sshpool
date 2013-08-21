package sshpool

import (
	"code.google.com/p/go.crypto/ssh"
	"net"
	"strconv"
	"sync"
	"time"
)

// Open opens a new SSH session on the given server using DefaultPool.
func Open(net, addr string, config *ssh.ClientConfig) (*ssh.Session, error) {
	return DefaultPool.Open(net, addr, config)
}

type Pool struct {
	// If nil, net.Dialer is used with the given Timeout.
	Dial func(net, addr string) (net.Conn, error)

	// Computes a key to distinguish ssh connections.
	// If nil, AddrUserKey is used.
	Key func(net, addr string, config *ssh.ClientConfig) string

	// Timeout for Open (for both new and existing
	// connections). If Dial is not nil, it is up to the Dial func
	// to enforce the timeout for new connections.
	Timeout time.Duration

	tab map[string]*conn
	mu  sync.Mutex
}

var DefaultPool = new(Pool)

// Open starts a new SSH session on the given server, reusing
// an existing connection if possible. If no connection exists,
// or if opening the session fails, Open attempts to dial a new
// connection. If dialing fails, Open returns the error from Dial.
func (p *Pool) Open(net, addr string, config *ssh.ClientConfig) (*ssh.Session, error) {
	var deadline, sessionDeadline time.Time
	if p.Timeout > 0 {
		now := time.Now()
		deadline = now.Add(p.Timeout)

		// First time, use a NewSession deadline at half of the
		// overall timeout, to try to leave time for a subsequent
		// Dial and NewSession.
		sessionDeadline = now.Add(p.Timeout / 2)
	}
	k := p.key(net, addr, config)
	for {
		c := p.getConn(k, net, addr, config, deadline)
		if c.err != nil {
			p.removeConn(k, c)
			return nil, c.err
		}
		s, err := c.newSession(sessionDeadline)
		if err == nil {
			return s, nil
		}
		sessionDeadline = deadline
		p.removeConn(k, c)
		c.c.Close()
		if p.Timeout > 0 && time.Now().After(deadline) {
			return nil, err
		}
	}
}

type conn struct {
	netC net.Conn
	c    *ssh.ClientConn
	ok   chan bool
	err  error
}

func (c *conn) newSession(deadline time.Time) (*ssh.Session, error) {
	if !deadline.IsZero() {
		c.netC.SetDeadline(deadline)
		defer c.netC.SetDeadline(time.Time{})
	}
	return c.c.NewSession()
}

// getConn gets an ssh connection from the pool for key.
// If none is available, it dials anew.
func (p *Pool) getConn(k, net, addr string, config *ssh.ClientConfig, deadline time.Time) *conn {
	p.mu.Lock()
	if p.tab == nil {
		p.tab = make(map[string]*conn)
	}
	c, ok := p.tab[k]
	if ok {
		p.mu.Unlock()
		<-c.ok
		return c
	}
	c = &conn{ok: make(chan bool)}
	p.tab[k] = c
	p.mu.Unlock()
	c.netC, c.c, c.err = p.dial(net, addr, config, deadline)
	close(c.ok)
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

func (p *Pool) dial(network, addr string, config *ssh.ClientConfig, deadline time.Time) (net.Conn, *ssh.ClientConn, error) {
	dial := p.Dial
	if dial == nil {
		dialer := net.Dialer{Deadline: deadline}
		dial = dialer.Dial
	}
	netC, err := dial(network, addr)
	if err != nil {
		return nil, nil, err
	}
	sshC, err := ssh.Client(netC, config)
	if err != nil {
		netC.Close()
		return nil, nil, err
	}
	return netC, sshC, nil
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
