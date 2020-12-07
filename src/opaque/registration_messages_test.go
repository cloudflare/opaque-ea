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

func TestMarshalUnmarshalRegistrationRequest(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	regReq1 := &RegistrationRequest{
		UserID:   []byte("username"),
		OprfData: oprfData,
	}

	regReq2 := &RegistrationRequest{}
	if err := TestMarshalUnmarshal(regReq1, regReq2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalRegistrationResponse(t *testing.T) {
	oprfData := make([]byte, 32)
	_, _ = rand.Read(oprfData)

	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
	}

	regResp1 := &RegistrationResponse{
		OprfData:        oprfData,
		ServerPublicKey: signer.Public(),
		CredentialEncodingPolicy: &CredentialEncodingPolicy{
			SecretTypes:    []CredentialType{CredentialTypeUserPrivateKey},
			CleartextTypes: []CredentialType{CredentialTypeServerIdentity, CredentialTypeServerPublicKey},
		},
	}
	regResp2 := &RegistrationResponse{}

	if err := TestMarshalUnmarshal(regResp1, regResp2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalRegistrationUpload(t *testing.T) {
	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	regUpload1 := &RegistrationUpload{
		Envelope:      getDummyEnvelope(),
		UserPublicKey: signer.Public(),
	}

	regUpload2 := &RegistrationUpload{}
	if err := TestMarshalUnmarshal(regUpload1, regUpload2); err != nil {
		t.Error(err)
		return
	}
}
