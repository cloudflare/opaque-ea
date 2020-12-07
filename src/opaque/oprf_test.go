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
	"bytes"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/tatianab/mint"
)

func TestOPRFFlow(t *testing.T) {
	username := "alice"
	password := "wonderland"
	domain := "bob.com"

	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
	}

	s, err := NewServer(&ServerConfig{Signer: signer, ServerID: domain, Suite: oprf.OPRFP256})
	if err != nil {
		t.Errorf("new server error: %v", err)
	}

	expectedRwd, err := RunLocalOPRF(s, username, password)
	if err != nil {
		t.Errorf("could not get expected rwd: %v", err)
	}

	_, err = s.InsertNewUserRecord(nil, nil) // some contents don't matter for this test
	if err != nil {
		t.Error(err)
	}

	client, err := NewClient(username, domain, oprf.OPRFP256)
	if err != nil {
		t.Errorf("new client error: %v", err)
	}

	oprf1, err := client.blind(password)
	if err != nil {
		t.Errorf("client OPRF init error: %v", err)
	}

	oprf2, err := s.evaluate(oprf1)
	if err != nil {
		t.Errorf("server OPRF init error: %v", err)
	}

	rwd, err := client.finalizeHarden(oprf2)
	if err != nil {
		t.Errorf("client OPRF finish error: %v", err)
	}

	if !bytes.Equal(rwd, expectedRwd) {
		t.Errorf("incorrect rwd: expected %v, got %v", expectedRwd, rwd)
	}
}
