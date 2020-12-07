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
	"crypto/rand"
	"errors"
	"testing"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
	"github.com/cloudflare/opaque-ea/src/testhelp"

	"github.com/cloudflare/circl/oprf"
	"github.com/tatianab/mint"
)

// getDummyEA returns a dummy Exported Authenticator for testing.
func getDummyEA() *expauth.ExportedAuthenticator {
	hashLen := common.HashMap[expauth.ExpAuthTestSignatureScheme].Size()

	return &expauth.ExportedAuthenticator{
		CertMsg: &mint.CertificateBody{
			CertificateRequestContext: []byte("test context"),
			CertificateList:           []mint.CertificateEntry{},
		},
		CertVerify: &mint.CertificateVerifyBody{
			Algorithm: expauth.ExpAuthTestSignatureScheme,
			Signature: []byte{},
		},
		Finished: &mint.FinishedBody{
			VerifyDataLen: hashLen,
			VerifyData:    make([]byte, hashLen),
		},
	}
}

func getDummyEAWithPSAE(scheme mint.SignatureScheme) (*expauth.ExportedAuthenticator, error) {
	ea := getDummyEA()
	el := mint.ExtensionList{}

	oprfMsg := make([]byte, 32)
	_, _ = rand.Read(oprfMsg)

	err := el.Add(&opaque.PAKEServerAuthExtension{
		PAKEShare: &opaque.PAKEShareClient{
			UserID:  []byte("user"),
			OprfMsg: oprfMsg,
		},
	})
	if err != nil {
		return nil, err
	}

	signer, x509cert, _ := mint.MakeNewSelfSignedCert("dummy", scheme)
	ea.CertMsg.CertificateList = []mint.CertificateEntry{
		{
			CertData:   x509cert,
			Extensions: el,
		},
	}

	ea.SetPublicKey(signer.Public())

	return ea, nil
}

func getDummyClientInitMsg() (*ClientInitMsg, error) {
	el := mint.ExtensionList{}

	oprfMsg := make([]byte, 32)
	_, _ = rand.Read(oprfMsg)

	err := el.Add(&opaque.PAKEServerAuthExtension{
		PAKEShare: &opaque.PAKEShareClient{
			UserID:  []byte("username"),
			OprfMsg: oprfMsg,
		},
		OPAQUEType: opaque.OPAQUESign,
	})
	if err != nil {
		return nil, err
	}

	srm := &ClientInitMsg{
		Request: &expauth.ClientExportedAuthenticatorRequest{
			CertificateRequestContext: []byte("test context"),
			Extensions:                el,
		},
	}

	return srm, nil
}

func getDummySvrMsg() (*ServerResponseMsg, error) {
	el := mint.ExtensionList{}

	err := el.Add(&opaque.PAKEClientAuthExtension{
		UserID: []byte("user"),
	})
	if err != nil {
		return nil, err
	}

	ea, err := getDummyEAWithPSAE(opaque.OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	srm := &ServerResponseMsg{
		ExpAuth: ea,
		Request: &expauth.ServerExportedAuthenticatorRequest{
			CertificateRequestContext: []byte("test context"),
			Extensions:                el,
		},
	}

	return srm, nil
}

func TestMarshalUnmarshalServerResponseMessage(t *testing.T) {
	srm1, err := getDummySvrMsg()
	if err != nil {
		t.Error(err)
		return
	}

	srm2 := &ServerResponseMsg{}
	if err := testhelp.TestMarshalUnmarshal(srm1, srm2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalClientInitMsg(t *testing.T) {
	cim1, err := getDummyClientInitMsg()
	if err != nil {
		t.Errorf("FAIL: dummy client msg: %v", err)
		return
	}

	cim2 := &ClientInitMsg{}
	if err := testhelp.TestMarshalUnmarshal(cim1, cim2); err != nil {
		t.Error(err)
		return
	}
}

func OPAQUEEASetup(username string) (*Client, *Server, error) {
	suite := oprf.OPRFP256
	domain := "demo.com"
	authHash := crypto.SHA512
	keyLen := 32
	k1 := common.GetRandomBytes(keyLen)
	k2 := common.GetRandomBytes(keyLen)
	k3 := common.GetRandomBytes(keyLen)
	k4 := common.GetRandomBytes(keyLen)
	getExportedKey := expauth.ExportedKeyGetterFromKeys(k1, k2, k3, k4)
	eaClient := expauth.ClientFromGetter(getExportedKey, authHash)

	client, err := NewClient(eaClient, username, domain, suite)
	if err != nil {
		return nil, nil, err
	}

	eaServer := expauth.ServerFromGetter(getExportedKey, authHash)

	cfg, err := opaque.NewTestServerConfig(domain, suite)
	if err != nil {
		return nil, nil, err
	}

	server, err := NewServer(eaServer, &ServerConfig{OpaqueCfg: cfg})
	if err != nil {
		return nil, nil, err
	}

	return client, server, nil
}

func TestOPAQUE_EAFlow(t *testing.T) {
	username := "newUser"
	password := "aPassword"

	client, server, err := OPAQUEEASetup(username)
	if err != nil {
		t.Errorf("SETUP ERROR: %v", err)
		return
	}

	// REGISTRATION FLOW
	clientSigner, err := mint.NewSigningKey(opaque.OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	regRequest, err := client.RegistrationRequest(password, clientSigner)
	if err != nil {
		t.Error(err)
		return
	}

	regResponse, err := server.RegistrationResponse(regRequest)
	if err != nil {
		t.Error(err)
		return
	}

	regUpload, err := client.FinalizeRegistration(regResponse)
	if err != nil {
		t.Error(err)
		return
	}

	err = server.UploadCredentials(regUpload)
	if err != nil {
		t.Error(err)
		return
	}

	// LOGIN FLOW

	clientRequest, err := client.Request(password)
	if err != nil {
		t.Errorf("CLIENT ERROR: %v", err)
		return
	}

	serverResponse, err := server.Respond(clientRequest)
	if err != nil {
		t.Errorf("SERVER ERROR: %v", err)
		return
	}

	clientResponse, err := client.VerifyAndRespond(serverResponse)
	if err != nil {
		t.Errorf("CLIENT ERROR: %v", err)
		return
	}

	err = server.Verify(clientResponse)
	if err != nil {
		t.Errorf("VERIFY FAILED: %v", err)
		return
	}
}

func TestBadPasswordOPAQUE_EAFlow(t *testing.T) {
	username := testhelp.TestUser

	client, server, err := OPAQUEEASetup(username)
	if err != nil {
		t.Errorf("SETUP ERROR: %v", err)
		return
	}

	wrongPassword := "password2"

	clientMsg1, err := client.Request(wrongPassword)
	if err != nil {
		t.Errorf("CLIENT ERROR: %v", err)
		return
	}

	serverMsg1, err := server.Respond(clientMsg1)
	if err != nil {
		t.Errorf("SERVER ERROR: %v", err)
		return
	}

	_, err = client.VerifyAndRespond(serverMsg1)
	if err == nil || !errors.Is(err, common.ErrorBadEnvelope) {
		t.Errorf("expected error to contain '%v', got %v", common.ErrorBadEnvelope, err)
		return
	}

	serverMsgBody, err := serverMsg1.ToBody()
	if err != nil {
		t.Error(err)
		return
	}

	fakeKey, err := mint.NewSigningKey(opaque.OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	clientMsgBody, err := client.mutualAuthResponse(serverMsgBody.(*ServerResponseMsg).Request, fakeKey)
	if err != nil {
		t.Error(err)
		return
	}

	clientMsg2, err := ProtocolMessageFromBody(clientMsgBody)
	if err != nil {
		t.Error(err)
		return
	}

	err = server.Verify(clientMsg2)
	if err == nil || !errors.Is(err, common.ErrorInvalidAuthenticator) {
		t.Errorf("expected error to contain '%v', got %v", common.ErrorInvalidAuthenticator, err)
		return
	}
}

func TestBadEnvelopeOPAQUE_EAFlow(t *testing.T) {
	username := testhelp.TestUser
	password := testhelp.TestPassword

	client, server, err := OPAQUEEASetup(username)
	if err != nil {
		t.Errorf("SETUP ERROR: %v", err)
		return
	}

	clientMsg1, err := client.Request(password)
	if err != nil {
		t.Errorf("CLIENT ERROR: %v", err)
		return
	}

	clientMsgBody, err := clientMsg1.ToBody()
	if err != nil {
		t.Error(err)
		return
	}

	// Wrong password file
	serverMsgBody, err := server.respondToWrongUser(clientMsgBody.(*ClientInitMsg), "user2")
	if err != nil {
		t.Errorf("SERVER ERROR: %v", err)
		return
	}

	serverMsg1, err := ProtocolMessageFromBody(serverMsgBody)
	if err != nil {
		t.Error(err)
		return
	}

	_, err = client.VerifyAndRespond(serverMsg1)
	if err == nil || !errors.Is(err, common.ErrorBadEnvelope) {
		t.Errorf("expected error to contain '%v', got %v", common.ErrorBadEnvelope, err)
		return
	}
}

func (s *Server) respondToWrongUser(clientMsg *ClientInitMsg, username string) (*ServerResponseMsg, error) {
	clientPAKEShare, err := s.extractClientPAKEShare(clientMsg.Request)
	if err != nil {
		return nil, err
	}

	// Construct EA with PAKEServerAuth extension, containing user_id, OPRF_2, vU and EnvU, signed with keyPair
	ea, err := s.getAuthenticator(clientPAKEShare.OprfMsg, []byte(username), clientMsg.Request)
	if err != nil {
		return nil, err
	}

	// Construct EAReq with PAKEClientAuth extension, containing user_id
	request, err := s.getMutualAuthenticationRequest(clientMsg.Request, clientPAKEShare.UserID)
	if err != nil {
		return nil, err
	}

	return &ServerResponseMsg{ExpAuth: ea, Request: request}, nil
}
