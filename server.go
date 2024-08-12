package ldapserver

import (
	"bufio"
	"fmt"
	"net"
	"sync"
	"time"
)

// Server is an LDAP server.
type Server struct {
	ReadTimeout  time.Duration  // optional read timeout
	WriteTimeout time.Duration  // optional write timeout
	wg           sync.WaitGroup // group of goroutines (1 by client)
	chDone       chan bool      // Channel Done, value => shutdown

	// HandleConnection is called on new connections.
	HandleConnection func(c net.Conn) Handler

	// DebugLogger can be useful for development.
	DebugLogger func(string)

	mu        sync.Mutex
	listeners map[*net.Listener]struct{}
}

// NewServer return a LDAP Server
func NewServer() *Server {
	return &Server{
		chDone: make(chan bool),
	}
}

func (s *Server) log(msg string) {
	if s.DebugLogger != nil {
		s.DebugLogger(msg)
	}
}

func (s *Server) logf(format string, a ...any) {
	if s.DebugLogger != nil {
		s.DebugLogger(fmt.Sprintf(format, a...))
	}
}

// ListenAndServe listens on the TCP network address s.Addr and then
// calls Serve to handle requests on incoming connections.  If
// s.Addr is blank, ":389" is used.
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = ":389"
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	return s.Serve(listener)
}

func (s *Server) Serve(listener net.Listener) error {
	if s.HandleConnection == nil {
		return fmt.Errorf("no LDAP Request Handler defined")
	}

	s.mu.Lock()
	if s.listeners == nil {
		s.listeners = make(map[*net.Listener]struct{})
	}
	s.listeners[&listener] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.listeners, &listener)
		s.mu.Unlock()
	}()

	i := 0

	for {
		rw, err := listener.Accept()
		if err != nil {
			// Temporary is deprecated, but still used by net/http (2024-08-10)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return err
		}

		if s.ReadTimeout > 0 {
			rw.SetReadDeadline(time.Now().Add(s.ReadTimeout))
		}
		if s.WriteTimeout > 0 {
			rw.SetWriteDeadline(time.Now().Add(s.WriteTimeout))
		}

		i++
		cli := &client{
			Numero: i,
			srv:    s,
			rwc:    rw,
			br:     bufio.NewReader(rw),
			bw:     bufio.NewWriter(rw),
		}

		s.logf("Connection client [%d] from %s accepted", cli.Numero, cli.rwc.RemoteAddr().String())
		s.wg.Add(1)
		go cli.serve()
	}
}

// Termination of the LDAP session is initiated by the server sending a
// Notice of Disconnection.  In this case, each
// protocol peer gracefully terminates the LDAP session by ceasing
// exchanges at the LDAP message layer, tearing down any SASL layer,
// tearing down any TLS layer, and closing the transport connection.
// A protocol peer may determine that the continuation of any
// communication would be pernicious, and in this case, it may abruptly
// terminate the session by ceasing communication and closing the
// transport connection.
// In either case, when the LDAP session is terminated.
func (s *Server) Shutdown() {
	s.mu.Lock()
	for listener := range s.listeners {
		(*listener).Close()
	}
	clear(s.listeners)
	s.mu.Unlock()
	close(s.chDone)
	s.log("gracefully closing client connections...")
	s.wg.Wait()
	s.log("all clients connection closed")
}
