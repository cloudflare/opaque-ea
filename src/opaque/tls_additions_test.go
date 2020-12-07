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

	"github.com/cloudflare/opaque-ea/src/common"
)

func TestMarshalUnmarshalPSAEServerShare(t *testing.T) {
	psae1 := &PAKEServerAuthExtension{
		PAKEShare: &PAKEShareServer{
			ServerID: []byte("example.com"),
			OprfMsg:  common.GetRandomBytes(32),
			Envelope: getDummyEnvelope(),
		},
	}
	psae2 := &PAKEServerAuthExtension{}

	if err := TestMarshalUnmarshal(psae1, psae2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalPSAEClientShare(t *testing.T) {
	oprfMsg := make([]byte, 32)
	_, _ = rand.Read(oprfMsg)

	psae1 := &PAKEServerAuthExtension{
		PAKEShare: &PAKEShareClient{
			UserID:  []byte("username"),
			OprfMsg: oprfMsg,
		},
	}
	psae2 := &PAKEServerAuthExtension{}

	if err := TestMarshalUnmarshal(psae1, psae2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalPCAE(t *testing.T) {
	pcae1 := &PAKEClientAuthExtension{
		UserID: []byte("username"),
	}
	pcae2 := &PAKEClientAuthExtension{}

	if err := TestMarshalUnmarshal(pcae1, pcae2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalPAKEShareServer(t *testing.T) {
	pss1 := &PAKEShareServer{
		ServerID: []byte("example.com"),
		OprfMsg:  common.GetRandomBytes(32),
		Envelope: getDummyEnvelope(),
	}
	pss2 := &PAKEShareServer{}

	if err := TestMarshalUnmarshal(pss1, pss2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalPAKEShareClient(t *testing.T) {
	oprfMsg := make([]byte, 32)
	_, _ = rand.Read(oprfMsg)

	psc1 := &PAKEShareClient{
		UserID:  []byte("username"),
		OprfMsg: oprfMsg,
	}
	psc2 := &PAKEShareClient{}

	if err := TestMarshalUnmarshal(psc1, psc2); err != nil {
		t.Error(err)
		return
	}
}
