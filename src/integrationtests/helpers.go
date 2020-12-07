// Copyright (c) 2020, Cloudflare. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package integrationtests

import (
	"crypto/x509"
	"log"
	"net"
	"time"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

const (
	// ServerLogContext represents the log context of a server.
	ServerLogContext = "server"
	// ClientLogContext represents the log context of a client.
	ClientLogContext = "client"
)

// IntegrationTest starts a TLS client and server and runs the provided test code.
func IntegrationTest(runClient, runServer func(*mint.Conn, []*mint.Certificate) error, scheme mint.SignatureScheme) error {
	serverError := make(chan error, 1)
	done := make(chan bool, 1)
	exampleDomain := "example.com"
	exampleDomain2 := "example2.com"
	roots := x509.NewCertPool()

	certs, err := common.SelfSignedCerts(exampleDomain, roots)
	if err != nil {
		return err
	}

	eaCert, err := common.SelfSignedCert(exampleDomain2, roots, scheme)
	if err != nil {
		return err
	}

	eaCerts := []*mint.Certificate{eaCert}
	serverCfg := &mint.Config{Certificates: certs, RootCAs: roots}

	// Local TCP+TLS connection (Server)
	go func() {
		listener, err := net.Listen("tcp", "localhost:8000")
		if err != nil {
			serverError <- err
			return
		}

		serverConn, err := listener.Accept()
		if err != nil {
			serverError <- err
			return
		}

		server := mint.Server(serverConn, serverCfg)

		defer func() {
			// Server closes
			listener.Close()
			server.Close()
			log.Println("Server connection closed.")
			done <- true
		}()

		if alert := server.Handshake(); alert != mint.AlertNoAlert {
			serverError <- errors.Wrap(alert, "server handshake")
			return
		}

		// Run post-hanshake server code
		err = runServer(server, eaCerts)
		if err == nil {
			log.Println(color.GreenString("SERVER SUCCEEDED"))
			serverError <- nil
		} else {
			log.Println(color.RedString("SERVER FAILED: %v", err))
			serverError <- err
		}
	}()

	time.Sleep(1 * time.Second)

	// Start local client
	clientCfg := &mint.Config{
		ServerName: exampleDomain,
		RootCAs:    roots,
	}

	client, err := mint.Dial("tcp", "localhost:8000", clientCfg)
	if err != nil {
		return errors.Wrap(err, "client dial")
	}

	defer func() {
		client.Close()
		log.Println("Client connection closed.")
		// Wait for server to finish
		<-done
	}()

	log.Println("Successful TLS handshake complete.")

	// Run post-handshake client code
	err = runClient(client, eaCerts)
	if err == nil {
		log.Println(color.GreenString("CLIENT SUCCEEDED"))

		sError := <-serverError

		return sError
	}

	log.Println(color.RedString("CLIENT FAILED: %v", err))

	return err
}
