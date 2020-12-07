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
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

func TestMain(m *testing.M) {
	// Turn off logging
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func TestInvalidEAIntegration(t *testing.T) {
	err := IntegrationTest(runEAClientResponderBad, runEAServerRequestor, expauth.ExpAuthTestSignatureScheme)
	if err == nil || !errors.Is(err, common.ErrorInvalidFinishedMac) {
		t.Errorf("expected error to contain %s, got %v", common.ErrorInvalidFinishedMac, err)
	}
}

func TestEmptyEAIntegration(t *testing.T) {
	err := IntegrationTest(runEAClientResponderEmpty, runEAServerRequestor, expauth.ExpAuthTestSignatureScheme)
	if err == nil {
		t.Errorf("Exported Authenticator should be invalid")
	}
}

func TestEAIntegrationServerAuth(t *testing.T) {
	err := IntegrationTest(runEAClientRequestor, runEAServerResponderGood, expauth.ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func TestEAIntegrationServerSpontaneousAuth(t *testing.T) {
	err := IntegrationTest(runEAClientRequestorNoRequest, runEAServerResponderNoRequest, expauth.ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("%v", err)
	}
}
func TestEAIntegrationClientAuth(t *testing.T) {
	err := IntegrationTest(runEAClientResponderGood, runEAServerRequestor, expauth.ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func runEAServerRequestor(server *mint.Conn, cert []*mint.Certificate) error {
	return runEARequestor(server, false, nonEmptyAuth)
}

func runEAClientRequestor(client *mint.Conn, cert []*mint.Certificate) error {
	return runEARequestor(client, true, nonEmptyAuth)
}

func runEAClientRequestorNoRequest(client *mint.Conn, cert []*mint.Certificate) error {
	return runEARequestor(client, true, noRequest)
}

func runEAServerResponderGood(server *mint.Conn, cert []*mint.Certificate) error {
	return runEAResponder(server, cert, false, nonEmptyAuth)
}

func runEAServerResponderNoRequest(server *mint.Conn, cert []*mint.Certificate) error {
	return runEAResponder(server, cert, false, noRequest)
}

func runEAClientResponderGood(client *mint.Conn, cert []*mint.Certificate) error {
	return runEAResponder(client, cert, true, nonEmptyAuth)
}

func runEAClientResponderBad(client *mint.Conn, cert []*mint.Certificate) error {
	return runEAResponder(client, cert, true, badAuth)
}

func runEAClientResponderEmpty(client *mint.Conn, cert []*mint.Certificate) error {
	return runEAResponder(client, cert, true, emptyAuth)
}

const (
	emptyAuth int = 1 + iota
	nonEmptyAuth
	badAuth
	noRequest
)

func runEARequestor(conn *mint.Conn, isClient bool, option int) error {
	var request expauth.ExportedAuthenticatorRequest
	var err error

	party := ServerLogContext
	newEAParty := expauth.Server

	if isClient {
		party = ClientLogContext
		newEAParty = expauth.Client
	}

	log.Printf("Running EA %v...\n", party)

	// Party starts an EA instance
	eaParty := newEAParty(conn)

	if option != noRequest {
		// Party creates request for authenticator and sends over TLS channel
		request, err = eaParty.Request(common.GetExtensionListFromSignatureScheme(expauth.ExpAuthTestSignatureScheme))
		if err != nil {
			return err
		}

		log.Printf("%v sending EA request...\n", strings.Title(party))

		rawRequest, err := request.Marshal()
		if err != nil {
			return errors.Wrapf(err, "%v", party)
		}

		_, err = conn.Write(rawRequest)
		if err != nil {
			return errors.Wrapf(err, "%v", party)
		}
	}

	// Party waits for an Exported Authenticator
	buf := make([]byte, 1500)

	_, err = conn.Read(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	ea := &expauth.ExportedAuthenticator{}

	_, err = ea.Unmarshal(buf)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	// Party validates EA
	log.Printf("%v validating EA...\n", strings.Title(party))

	if option != noRequest {
		_, _, err = eaParty.Validate(ea, request)
	} else {
		_, _, err = eaParty.Validate(ea, nil)
	}

	return err
}

func runEAResponder(conn *mint.Conn, cert []*mint.Certificate, isClient bool, option int) error {
	var request expauth.ExportedAuthenticatorRequest

	party := ServerLogContext
	request = &expauth.ClientExportedAuthenticatorRequest{}
	newEAParty := expauth.Server

	if isClient {
		party = ClientLogContext
		request = &expauth.ServerExportedAuthenticatorRequest{}
		newEAParty = expauth.Client
	}

	log.Printf("Running EA %v as a Responder...", party)

	// Party waits for authenticator request
	if option != noRequest {
		buf := make([]byte, 1500)

		_, err := conn.Read(buf)
		if err != nil {
			return errors.Wrapf(err, "%v", party)
		}

		_, err = request.Unmarshal(buf)
		if err != nil {
			return errors.Wrapf(err, "%v", party)
		}
	}

	// Party starts an EA instance
	eaParty := newEAParty(conn)

	// Party responds with exported authenticator
	log.Printf("%v sending exported authenticator...", strings.Title(party))

	var rawEA []byte
	var ea *expauth.ExportedAuthenticator
	var err error

	switch option {
	case noRequest:
		ea, err = eaParty.AuthenticateSpontaneously(cert, nil)
	case emptyAuth:
		ea, err = eaParty.RefuseAuthentication(request)
	case nonEmptyAuth:
		ea, err = eaParty.Authenticate(cert, nil, request)
	case badAuth:
		ea, err = eaParty.Authenticate(cert, nil, request)
		if err != nil {
			return errors.Wrapf(err, "%v", party)
		}

		ea.Finished.VerifyData[1] = byte(2) // corrupt a byte
	}

	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	rawEA, err = ea.Marshal()
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	_, err = conn.Write(rawEA)
	if err != nil {
		return errors.Wrapf(err, "%v", party)
	}

	return nil
}
