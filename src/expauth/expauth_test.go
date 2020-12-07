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

package expauth

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/testhelp"
	"github.com/tatianab/mint"
)

func getDummyEA(sigScheme mint.SignatureScheme) *ExportedAuthenticator {
	authHash := common.HashMap[sigScheme]

	return &ExportedAuthenticator{
		CertMsg: &mint.CertificateBody{
			CertificateRequestContext: common.GetRandomBytes(32),
			CertificateList:           []mint.CertificateEntry{},
		},
		CertVerify: &mint.CertificateVerifyBody{
			Algorithm: sigScheme,
			Signature: []byte{},
		},
		Finished: &mint.FinishedBody{
			VerifyDataLen: authHash.Size(),
			VerifyData:    make([]byte, authHash.Size()),
		},
	}
}

func getDummyEmptyEA(sigScheme mint.SignatureScheme) *ExportedAuthenticator {
	authHash := common.HashMap[sigScheme]

	return &ExportedAuthenticator{
		Finished: &mint.FinishedBody{
			VerifyDataLen: authHash.Size(),
			VerifyData:    make([]byte, authHash.Size()),
		},
	}
}

func TestMarshalUnmarshalExportedAuthenticator(t *testing.T) {
	ea1 := getDummyEA(ExpAuthTestSignatureScheme)

	ea2 := &ExportedAuthenticator{}
	if err := testhelp.TestMarshalUnmarshal(ea1, ea2); err != nil {
		t.Error(err)
	}
}

func TestMarshalUnmarshalEmptyExportedAuthenticator(t *testing.T) {
	ea1 := getDummyEmptyEA(ExpAuthTestSignatureScheme)

	ea2 := &ExportedAuthenticator{}
	if err := testhelp.TestMarshalUnmarshal(ea1, ea2); err != nil {
		t.Error(err)
	}
}

func TestMarshalUnmarshalExportedAuthenticatorWithTailData(t *testing.T) {
	ea1 := getDummyEA(ExpAuthTestSignatureScheme)
	ea2 := &ExportedAuthenticator{}

	mea1, err := ea1.Marshal()
	if err != nil {
		t.Errorf("FAIL: Marshal failed: %v", err)
		return
	}

	if _, err := ea2.Unmarshal(append(mea1, make([]byte, 10)...)); err != nil {
		t.Errorf("FAIL: Unmarshal failed: %v", err)
		return
	}

	if !reflect.DeepEqual(ea1, ea2) {
		t.Errorf("FAIL: Unmarshal returned different values: \n original %v \n unmarshaled %v",
			ea1, ea2)
	}
}

func TestExportedAuthenticatorFlow(t *testing.T) {
	getExportedKey, authHash := GetTestGetterAndHash()
	client := ClientFromGetter(getExportedKey, authHash)
	server := ServerFromGetter(getExportedKey, authHash)

	// Client requests an EA from Server
	request, err := client.Request(common.GetExtensionListFromSignatureSchemes(common.MintSupportedSignatureSchemes))
	if err != nil {
		t.Errorf("could not create EA request: %v", err)
	}

	// Server replies with an EA
	certs, err := common.SelfSignedCerts("example.com", nil)
	if err != nil {
		t.Errorf("could not get cert chain: %v", err)
	}

	ea, err := server.Authenticate(certs, nil, request)
	if err != nil {
		t.Errorf("could not create EA: %v", err)
	}

	// Client validates server's EA
	_, _, err = client.Validate(ea, request)
	if err != nil {
		t.Errorf("EA invalid: %v", err)
	}
}

func TestEAFlowServerRequest(t *testing.T) {
	client, server := getTestClientServer()

	request, err := server.Request(common.GetExtensionListFromSignatureScheme(ExpAuthTestSignatureScheme))
	if err != nil {
		t.Errorf("could not create EA request: %v", err)
	}

	cert, err := common.SelfSignedCert("example.com", nil, ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("could not get cert chain: %v", err)
	}

	ea, err := client.Authenticate([]*mint.Certificate{cert}, nil, request)
	if err != nil {
		t.Errorf("could not create EA: %v", err)
	}

	// validate EA
	_, _, err = server.Validate(ea, request)

	if err != nil {
		t.Errorf("EA invalid: %v", err)
	}
}

func TestEAFlowServerSpontaneous(t *testing.T) {
	client, server := getTestClientServer()

	cert, err := common.SelfSignedCert("example.com", nil, ExpAuthTestSignatureScheme)
	if err != nil {
		t.Errorf("could not get cert chain: %v", err)
	}

	ea, err := server.AuthenticateSpontaneously([]*mint.Certificate{cert}, nil)
	if err != nil {
		t.Errorf("could not create EA: %v", err)
	}

	// validate EA
	_, _, err = client.Validate(ea, nil)

	if err != nil {
		t.Errorf("EA invalid: %v", err)
	}
}

func TestEAFlowClientRequestServerReject(t *testing.T) {
	client, server := getTestClientServer()

	// Client requests an EA from Server
	request, err := client.Request(common.GetExtensionListFromSignatureScheme(ExpAuthTestSignatureScheme))
	if err != nil {
		t.Errorf("could not create EA request: %v", err)
	}

	// Server replies
	ea, err := server.RefuseAuthentication(request)
	if err != nil {
		t.Errorf("could not create EA: %v", err)
	}

	// Client checks EA
	certs, _, err := client.Validate(ea, request)

	if len(certs) > 0 {
		t.Errorf("certs should be empty")
	}
	if err == nil {
		t.Errorf("EA should be invalid")
	}
}

func TestRejectReusedContext(t *testing.T) {
	client, server := getTestClientServer()

	request, err := EAFlowClientRequest(client, server)
	if err != nil {
		t.Errorf("First EA flow failed: %v", err)
	}

	_, err = client.newAuthenticatorSession(request)
	if err == nil || !errors.Is(err, common.ErrorInvalidContext) {
		t.Errorf("expected error to contain '%v', got %v", common.ErrorInvalidContext, err)
	}

	_, err = server.newAuthenticatorSession(request)
	if err == nil || !errors.Is(err, common.ErrorInvalidContext) {
		t.Errorf("expected error to contain '%v', got %v", common.ErrorInvalidContext, err)
	}
}

func EAFlowClientRequest(client, server *Party) (ExportedAuthenticatorRequest, error) {
	// Client requests an EA from Server
	request, err := client.Request(common.GetExtensionListFromSignatureScheme(ExpAuthTestSignatureScheme))
	if err != nil {
		return nil, err
	}

	// Server replies
	cert, err := common.SelfSignedCert("example.com", nil, ExpAuthTestSignatureScheme)
	if err != nil {
		return nil, err
	}

	ea, err := server.Authenticate([]*mint.Certificate{cert}, nil, request)
	if err != nil {
		return nil, err
	}

	// Client checks EA
	_, _, err = client.Validate(ea, request)

	return request, err
}

func TestSupportedSignatureSchemes(t *testing.T) {
	getExportedKey, authHash := GetTestGetterAndHash()
	client := ClientFromGetter(getExportedKey, authHash)

	// Client requests an EA from Server
	request, err := client.Request(common.GetExtensionListFromSignatureSchemes(common.MintSupportedSignatureSchemes))
	if err != nil {
		t.Errorf("could not create EA request: %v", err)
	}

	gotSupportedSchemes, err := request.SupportedSignatureSchemes()
	if err != nil {
		t.Errorf("could not get supported schemes: %v", err)
	}

	if !reflect.DeepEqual(common.MintSupportedSignatureSchemes, gotSupportedSchemes) {
		t.Errorf("supported schemes do not match")
	}
}
