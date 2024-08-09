[![GoDoc](https://godoc.org/github.com/nolta/ldapserver?status.svg)](https://godoc.org/github.com/nolta/ldapserver)

**This package is a work in progress.**

**ldapserver** is a helper library for building server software capable of speaking the LDAP protocol. This could be an alternate implementation of LDAP, a custom LDAP proxy or even a completely different backend capable of "masquerading" its API as a LDAP Server.

The package supports 
* All basic LDAP Operations (bind, search, add, compare, modify, delete, extended)
* SSL
* StartTLS
* Unbind request is implemented, but is handled internally to close the connection.
* Graceful stopping
* Basic request routing inspired by [net/http ServeMux](http://golang.org/pkg/net/http/#ServeMux)
* Logger customisation (log interface)

# Default behaviors
## Abandon request
If you don't set a route to handle AbandonRequest, the package will handle it for you. (signal sent to message.Done chan)

## No Route Found
When no route matches the request, the server will first try to call a special *NotFound* route, if nothing is specified, it will return an *UnwillingToResponse* Error code (53)

Feel free to contribute, comment :)

#  Sample Code
```Go
// Listen to 10389 port for LDAP Request
// and route bind request to the handleBind func
package main

import (
	"log"
	"net"
	"os"
	"os/signal"

	ldap "github.com/nolta/ldapserver"
)

func main() {
	//ldap logger
	ldap.Logger = log.New(os.Stdout, "[server] ", log.LstdFlags)

	//Create a new LDAP Server
	server := ldap.NewServer()

	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	server.HandleConnection = func(net.Conn) ldap.Handler {
		return routes
	}

	// listen on 10389
	go server.ListenAndServe("127.0.0.1:10389")

	// stop server gracefully
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	<-ch
	close(ch)

	server.Stop()
}

// handleBind return Success if login == mysql
func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()
	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)

	if string(r.Name()) == "myLogin" {
		w.Write(res)
		return
	}

	log.Printf("Bind failed User=%s, Pass=%s", string(r.Name()), string(r.AuthenticationSimple()))
	res.SetResultCode(ldap.LDAPResultInvalidCredentials)
	res.SetDiagnosticMessage("invalid credentials")
	w.Write(res)
}
```

# more examples
Look into the "examples" folder
