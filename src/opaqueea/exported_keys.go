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

package opaqueea

import (
	"crypto"
	"log"
	"net/http"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/expauth"
)

// ExportedKeyMaterial represents an exported key material struct.
type ExportedKeyMaterial struct {
	ClientHandshakeContext []byte
	ServerHandshakeContext []byte
	ClientFinishedKey      []byte
	ServerFinishedKey      []byte
	AuthHash               crypto.Hash
}

// ToGetterAndHash casts an ExportedKeyMaterial into an ExportedKeyGetter.
func (ekm *ExportedKeyMaterial) ToGetterAndHash() (expauth.ExportedKeyGetter, crypto.Hash) {
	return expauth.ExportedKeyGetterFromKeys(ekm.ClientHandshakeContext, ekm.ClientFinishedKey,
		ekm.ServerHandshakeContext, ekm.ServerFinishedKey), ekm.AuthHash
}

// GetExportedKeyMaterial gets an ExportedKeyMaterial from a request.
func GetExportedKeyMaterial(request *http.Request) (*ExportedKeyMaterial, error) {
	if request.TLS != nil {
		getter := expauth.NewExportedKeyGetterFromTLSConnState(request.TLS)
		log.Printf("TLS connection: %v", request.TLS)
		authHash := expauth.AuthHashFromTLSConnState(request.TLS)

		return getExportedKeyMaterialInner(getter, authHash)
	}

	log.Printf("Not a TLS connection")
	return nil, nil
}

// GetTestExportedKeyMaterial gets an ExportedKeyMaterial for testing.
func GetTestExportedKeyMaterial() (*ExportedKeyMaterial, error) {
	getter, authHash := expauth.GetTestGetterAndHash()
	return getExportedKeyMaterialInner(getter, authHash)
}

func getExportedKeyMaterialInner(getter expauth.ExportedKeyGetter, authHash crypto.Hash) (*ExportedKeyMaterial, error) {
	chc, err := getter(expauth.ClientAuthMode, expauth.HandshakeLabel)
	if err != nil {
		return nil, err
	}

	cfk, err := getter(expauth.ClientAuthMode, expauth.FinishedLabel)
	if err != nil {
		return nil, err
	}

	shc, err := getter(expauth.ServerAuthMode, expauth.HandshakeLabel)
	if err != nil {
		return nil, err
	}

	sfk, err := getter(expauth.ServerAuthMode, expauth.FinishedLabel)
	if err != nil {
		return nil, err
	}

	return &ExportedKeyMaterial{
		ClientHandshakeContext: chc,
		ClientFinishedKey:      cfk,
		ServerHandshakeContext: shc,
		ServerFinishedKey:      sfk,
		AuthHash:               authHash,
	}, nil
}

// ConfigMaterial handles the material for a Config.
type ConfigMaterial struct {
	Suite oprf.SuiteID
}
