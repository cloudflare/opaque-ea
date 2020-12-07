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
	"log"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
	"github.com/cloudflare/opaque-ea/src/opaqueea"
	"github.com/cloudflare/opaque-ea/src/testhelp"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

const TestDomain string = "example.com"

func TestOpaqueEAIntegration(t *testing.T) {
	err := IntegrationTest(runOpaqueEAClient, runOpaqueEAServer, expauth.ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func runOpaqueEAServer(server *mint.Conn, cert []*mint.Certificate) error {
	log.Println("Running OPAQUE-EA Server...")

	// Set up EA server
	party := ServerLogContext
	eaServer := expauth.Server(server)

	// Set up OPAQUE-EA server
	domain := TestDomain
	suite := oprf.OPRFP256

	cfg, err := opaque.NewTestServerConfig(domain, suite)
	if err != nil {
		return err
	}

	s, err := opaqueea.NewServer(eaServer, &opaqueea.ServerConfig{OpaqueCfg: cfg})
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	// Server waits for OPAQUE exp-auth msg from Client
	log.Println("Server waiting for OPAQUE msg 1")

	buf := make([]byte, 1500)

	_, err = server.Read(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	clientInitMsg := &opaqueea.ProtocolMessage{}

	_, err = clientInitMsg.Unmarshal(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	// Server runs OPAQUE-EA Response protocol and sends messages over TLS Channel
	log.Println("Server running OPAQUE Response")

	// Get server response
	serverResponse, err := s.Respond(clientInitMsg)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	rawResponse, err := serverResponse.Marshal()
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	_, err = server.Write(rawResponse)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	//  Server waits for response
	log.Println("Server waiting for OPAQUE msg 2")

	buf = make([]byte, 1500)

	_, err = server.Read(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	clientResponse := &opaqueea.ProtocolMessage{}

	_, err = clientResponse.Unmarshal(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	// Server validates response with ServerVerify
	log.Println("Server verifying response")

	err = s.Verify(clientResponse)

	return err
}

func runOpaqueEAClient(client *mint.Conn, cert []*mint.Certificate) error {
	log.Println("Running OPAQUE-EA Client...")

	party := ClientLogContext
	suite := oprf.OPRFP256

	// Set up EA client
	eaClient := expauth.Client(client)

	// Client initiates OPAQUE-EA
	log.Println("Client initiating OPAQUE-EA.")

	// Set up client OPAQUE session
	c, err := opaqueea.NewClient(eaClient, testhelp.TestUser, TestDomain, suite)
	if err != nil {
		return err
	}

	initMsg, err := c.Request(testhelp.TestPassword)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	rawInitMsg, err := initMsg.Marshal()
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	_, err = client.Write(rawInitMsg)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	log.Println("Client waiting for response.")

	buf := make([]byte, 1500)

	_, err = client.Read(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	serverResponse := &opaqueea.ProtocolMessage{}

	_, err = serverResponse.Unmarshal(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	log.Println("Client verifying, and sending response.")

	response, err := c.VerifyAndRespond(serverResponse)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	rawResponse, err := response.Marshal()
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	_, err = client.Write(rawResponse)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	return nil
}
