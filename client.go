package ldapserver

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	ldap "github.com/lor00x/goldap/message"
)

type client struct {
	sync.Mutex
	Numero        int
	srv           *Server
	rwc           net.Conn
	br            *bufio.Reader
	bw            *bufio.Writer
	chanOut       chan *ldap.LDAPMessage
	wg            sync.WaitGroup
	closing       chan bool
	requestCancel map[int]context.CancelFunc
	writeDone     chan bool
}

func (c *client) GetConn() net.Conn {
	return c.rwc
}

func (c *client) SetConn(conn net.Conn) {
	c.rwc = conn
	c.br = bufio.NewReader(c.rwc)
	c.bw = bufio.NewWriter(c.rwc)
}

func (c *client) Addr() net.Addr {
	return c.rwc.RemoteAddr()
}

func (c *client) serve() {
	defer c.close()

	c.closing = make(chan bool)
	handler := c.srv.HandleConnection(c.rwc)
	if handler == nil {
		return
	}

	// Create the ldap response queue to be writted to client (buffered to 20)
	// buffered to 20 means that If client is slow to handler responses, Server
	// Handlers will stop to send more respones
	c.chanOut = make(chan *ldap.LDAPMessage)
	c.writeDone = make(chan bool)
	// for each message in c.chanOut send it to client
	go func() {
		for msg := range c.chanOut {
			c.writeMessage(msg)
		}
		close(c.writeDone)
	}()

	// Listen for server signal to shutdown
	go func() {
		for {
			select {
			case <-c.srv.chDone: // server signals shutdown process
				c.wg.Add(1)
				r := NewExtendedResponse(LDAPResultUnwillingToPerform)
				r.SetDiagnosticMessage("server is about to stop")
				r.SetResponseName(NoticeOfDisconnection)

				m := ldap.NewLDAPMessageWithProtocolOp(r)

				c.chanOut <- m
				c.wg.Done()
				c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
				return
			case <-c.closing:
				return
			}
		}
	}()

	// Incoming message channel. It's buffered so we can peek at
	// the next message, in case it's an AbandonRequest.
	//
	// XXX:FIXME enlarging the buffer may cause abandon requests to be
	// ignored, if they fire before the message starts processing.
	inbox := make(chan *ldap.LDAPMessage, 1)
	go func() {
		defer close(inbox)
		for {
			message, err := c.readMessage()
			if err != nil {
				c.srv.logf("client %d readMessage error: %s", c.Numero, err)
				return
			}

			switch message.ProtocolOp().(type) {
			case ldap.AbandonRequest:
				c.cancelMessageID(int(message.MessageID()))
			case ldap.UnbindRequest:
				return
			default:
				inbox <- message
			}
		}
	}()

	for message := range inbox {
		if c.srv.WriteTimeout > 0 {
			c.rwc.SetWriteDeadline(time.Now().Add(c.srv.WriteTimeout))
		}

		c.wg.Add(1)
		c.ProcessRequestMessage(handler, message)
	}
}

func (c *client) readMessage() (*ldap.LDAPMessage, error) {
	if c.srv.ReadTimeout > 0 {
		c.rwc.SetReadDeadline(time.Now().Add(c.srv.ReadTimeout))
	}

	//Read client input as a ASN1/BER binary message
	messagePacket, err := readMessagePacket(c.br)
	if err != nil {
		return nil, err
	}

	//Convert ASN1 binaryMessage to a ldap Message
	message, err := messagePacket.readMessage()
	if err != nil {
		return nil, err
	}

	return &message, nil
}

// close closes client,
// * stop reading from client
// * signals to all currently running request processor to stop
// * wait for all request processor to end
// * close client connection
// * signal to server that client shutdown is ok
func (c *client) close() {
	c.srv.logf("client %d close()", c.Numero)
	close(c.closing)

	// stop reading from client
	c.rwc.SetReadDeadline(time.Now().Add(time.Millisecond))
	c.srv.logf("client %d close() - stop reading from client", c.Numero)

	// signals to all currently running request processor to stop
	c.Lock()
	for messageID, cancelCtx := range c.requestCancel {
		c.srv.logf("Client %d close() - sent abandon signal to request[messageID = %d]", c.Numero, messageID)
		cancelCtx()
	}
	clear(c.requestCancel)
	c.Unlock()
	c.srv.logf("client %d close() - Abandon signal sent to processors", c.Numero)

	c.wg.Wait()      // wait for all current running request processor to end
	close(c.chanOut) // No more message will be sent to client, close chanOUT
	c.srv.logf("client [%d] request processors ended", c.Numero)

	<-c.writeDone // Wait for the last message sent to be written
	c.rwc.Close() // close client connection
	c.srv.logf("client [%d] connection closed", c.Numero)

	c.srv.wg.Done() // signal to server that client shutdown is ok
}

func (c *client) writeMessage(m *ldap.LDAPMessage) {
	data, _ := m.Write()
	c.srv.logf(">>> %d - %s - hex=%x", c.Numero, m.ProtocolOpName(), data.Bytes())
	c.bw.Write(data.Bytes())
	c.bw.Flush()
}

// ResponseWriter interface is used by an LDAP handler to
// construct an LDAP response.
type ResponseWriter interface {
	// Write writes the LDAPResponse to the connection as part of an LDAP reply.
	Write(po ldap.ProtocolOp)
}

type responseWriterImpl struct {
	chanOut   chan *ldap.LDAPMessage
	messageID int
}

func (w responseWriterImpl) Write(po ldap.ProtocolOp) {
	m := ldap.NewLDAPMessageWithProtocolOp(po)
	m.SetMessageID(w.messageID)
	w.chanOut <- m
}

func (c *client) ProcessRequestMessage(handler Handler, message *ldap.LDAPMessage) {
	defer c.wg.Done()

	messageID := message.MessageID().Int()
	m := &Message{
		LDAPMessage: message,
		Client:      c,
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// store the cancel function in case we get an abandon message
	c.Lock()
	if c.requestCancel == nil {
		c.requestCancel = make(map[int]context.CancelFunc)
	}
	c.requestCancel[messageID] = cancelCtx
	c.Unlock()
	defer func() {
		c.Lock()
		delete(c.requestCancel, messageID)
		c.Unlock()
	}()

	var w responseWriterImpl
	w.chanOut = c.chanOut
	w.messageID = messageID

	handler.ServeLDAP(ctx, w, m)
}

func (c *client) cancelMessageID(messageID int) {
	c.Lock()
	defer c.Unlock()
	if cancelCtx, ok := c.requestCancel[messageID]; ok {
		cancelCtx()
		delete(c.requestCancel, messageID)
	}
}
