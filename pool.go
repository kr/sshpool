package sshpool

import (
	"code.google.com/p/go.crypto/ssh"
	"log"
	"strconv"
	"sync"
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

	tab map[string]*ssh.ClientConn
	mu  sync.Mutex
}

var DefaultPool = new(Pool)

// Open opens a new SSH session on the given server, reusing
// an existing connection if possible. If no usable connection
// is available, Open attempts to dial a new connection. If this
// fails, Open returns an error.
func (p *Pool) Open(net, addr string, config *ssh.ClientConfig) (*ssh.Session, error) {
	k := p.key(net, addr, config)
	for {
		c, err := p.getConn(k, net, addr, config)
		if err != nil {
			return nil, err
		}
		s, err := c.NewSession()
		if err == nil {
			return s, nil
		}
		p.removeConn(k, c)
	}
}

// getConn gets an ssh connection from the pool for key.
// If none is available, it dials anew.
func (p *Pool) getConn(k, net, addr string, config *ssh.ClientConfig) (*ssh.ClientConn, error) {
	p.mu.Lock()
	if p.tab == nil {
		p.tab = make(map[string]*ssh.ClientConn)
	}
	c, ok := p.tab[k]
	p.mu.Unlock()
	if ok {
		return c, nil
	}

	// Another goroutine can be dialing the same k here.
	// We race to put a conn in the map, below.
	c1, err := p.dial(net, addr, config)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	c, ok = p.tab[k]
	if !ok {
		// We won the race. Insert our conn.
		c = c1
		p.tab[k] = c
	}
	p.mu.Unlock()
	if ok {
		// They won the race. Close our conn.
		log.Printf("sshpool: discarding unused conn: %q", k)
		c1.Close()
	}
	return c, nil
}

// removeConn removes c1 from the pool if present.
func (p *Pool) removeConn(k string, c1 *ssh.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.tab == nil {
		p.tab = make(map[string]*ssh.ClientConn)
	}
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
