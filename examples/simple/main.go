// Listen to 10389 port for LDAP Request
// and route bind request to the handleBind func
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	ldap "github.com/nolta/ldapserver"
)

func main() {

	//Create a new LDAP Server
	server := ldap.NewServer()

	// debug messages
	server.DebugLogger = func(s string) { log.New(os.Stdout, "[server] ", log.LstdFlags).Print(s) }

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	server.HandleConnection = func(net.Conn) ldap.Handler {
		return routes
	}

	// listen on 10389
	go server.ListenAndServe("127.0.0.1:10389")

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	server.Shutdown()
}

// handleBind return Success if login == mysql
func handleBind(ctx context.Context, w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "login" {
		// w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}
