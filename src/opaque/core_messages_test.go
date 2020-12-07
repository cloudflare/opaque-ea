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
	"crypto/rand"
	"testing"

	"github.com/tatianab/mint"
)

func TestMarshalUnmarshalProtocolMessage(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	cr1 := &CredentialRequest{
		UserID:   []byte("username"),
		OprfData: oprfData,
	}

	msg1, err := ProtocolMessageFromBody(cr1)
	if err != nil {
		t.Error(err)
		return
	}

	msg2 := &ProtocolMessage{}

	if err := TestMarshalUnmarshal(msg1, msg2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalCredentialRequest(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	cr1 := &CredentialRequest{
		UserID:   []byte("username"),
		OprfData: oprfData,
	}

	cr2 := &CredentialRequest{}
	if err := TestMarshalUnmarshal(cr1, cr2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalCredentialResponse(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	signer, err := mint.NewSigningKey(mint.ECDSA_P256_SHA256)
	if err != nil {
		t.Error(err)
		return
	}

	cr1 := &CredentialResponse{
		OprfData:        oprfData,
		Envelope:        getDummyEnvelope(),
		serverPublicKey: signer.Public(),
	}

	cr2 := &CredentialResponse{}
	if err := TestMarshalUnmarshal(cr1, cr2); err != nil {
		t.Error(err)
		return
	}
}
