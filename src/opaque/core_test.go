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

package opaque

import (
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

func TestOPAQUECore(t *testing.T) {
	err := RegisterAndRunOPAQUE(oprf.OPRFP256)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func RegisterAndRunOPAQUE(suite oprf.SuiteID) error {
	domain := "example.com"

	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		return err
	}

	cfg := &ServerConfig{
		ServerID:    domain,
		Signer:      signer,
		RecordTable: make(InMemoryUserRecordTable),
		Suite:       suite,
	}
	s, err := NewServer(cfg)
	if err != nil {
		return err
	}

	username := "user"
	password := []byte("password")
	c, err := NewClient(username, domain, suite)
	if err != nil {
		return errors.Wrap(err, "new client")
	}

	// REGISTRATION FLOW
	regRequest, err := c.CreateRegistrationRequest(string(password), signer)
	if err != nil {
		return errors.Wrap(err, "create reg request")
	}

	regResponse, err := s.CreateRegistrationResponse(regRequest)
	if err != nil {
		return errors.Wrap(err, "create reg response")
	}

	regUpload, _, err := c.FinalizeRegistrationRequest(regResponse)
	if err != nil {
		return errors.Wrap(err, "finalize request")
	}

	err = s.StoreUserRecord(regUpload)
	if err != nil {
		return errors.Wrap(err, "store user record")
	}

	// LOGIN FLOW
	// C -- (username, OPRF_1) --> S
	loginRequest, err := c.CreateCredentialRequest(password)
	if err != nil {
		return errors.Wrap(err, "create cred request")
	}
	// S -- (Envelope, OPRF_2) --> C
	loginResponse, err := s.CreateCredentialResponse(loginRequest)
	if err != nil {
		return errors.Wrap(err, "create cred response")
	}

	// C - finish OPRF and decrypt
	_, err = c.RecoverCredentials(loginResponse)
	if err != nil {
		return errors.Wrap(err, "recover creds")
	}

	// TODO: validation
	return nil
}
