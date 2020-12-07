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
	"bytes"
	"crypto"

	"github.com/pkg/errors"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
	"github.com/tatianab/mint"
)

/* For now, assuming mutual auth always happens. */
/* OPAQUE-EA FLOW
      Client	   		      ______m1_________	                  Server
m1 = c.Request(pwd) -------- | AuthRequest w/  | ------->
	  				         | (userID, oprf1) |
					          -----------------           m2 = s.Respond(m1)
			   		      __________m2______________
					     |       ExpAuth w/         |
					<--- | (svrID, oprf2, vU, EnvU) | ----
					     |  AuthRequest w/ (userID) |
ok, m3 = c.Respond(m2) 	  --------------------------
if !ok: abort			      ______m3________
					    ---- |    ExpAuth     | --->
					          ----------------           ok = s.Verify(m3)
*/

// Request returns the initial client message to be sent to the server.
func (c *Client) Request(password string) (*ProtocolMessage, error) {
	// Construct EARequest with PAKEServerAuth extension, containing user_id and OPRF_1
	// TODO: make this a parameter (potentially tie to existing TLS connection)
	supportedSchemes := &mint.SignatureAlgorithmsExtension{Algorithms: []mint.SignatureScheme{opaque.OPAQUESIGNSignatureScheme}}
	exts := mint.ExtensionList{}

	err := exts.Add(supportedSchemes)
	if err != nil {
		return nil, err
	}

	credRequest, err := c.opaqueState.CreateCredentialRequest([]byte(password))
	if err != nil {
		return nil, err
	}

	err = exts.Add(&opaque.PAKEServerAuthExtension{
		PAKEShare: &opaque.PAKEShareClient{
			UserID:  c.opaqueState.UserID,
			OprfMsg: credRequest.OprfData,
		},
		OPAQUEType: opaque.OPAQUESign,
	})
	if err != nil {
		return nil, err
	}

	request, err := c.eaState.Request(exts)
	if err != nil {
		return nil, err
	}

	c.request = request

	clientInitMsg, err := ProtocolMessageFromBody(&ClientInitMsg{Request: request})
	if err != nil {
		return nil, err
	}

	return clientInitMsg, nil
}

// Respond takes in the user password file and initial client message, and
// returns the server response message.
// TODO: make mutual auth optional.
func (s *Server) Respond(clientRequest *ProtocolMessage) (*ProtocolMessage, error) {
	protocolMessageBody, err := clientRequest.ToBody()
	if err != nil {
		return nil, err
	}

	clientInitMsg, ok := protocolMessageBody.(*ClientInitMsg)
	if !ok {
		return nil, common.ErrorUnexpectedMessage
	}

	clientPAKEShare, err := s.extractClientPAKEShare(clientInitMsg.Request)
	if err != nil {
		return nil, errors.Wrap(err, "extract PAKE share")
	}

	// Construct EA with PAKEServerAuth extension, containing user_id, OPRF_2, vU and EnvU, signed with keyPair
	ea, err := s.getAuthenticator(clientPAKEShare.OprfMsg, clientPAKEShare.UserID, clientInitMsg.Request)
	if err != nil {
		return nil, errors.Wrap(err, "get server ExpAuth")
	}

	// Construct EAReq with PAKEClientAuth extension, containing user_id
	request, err := s.getMutualAuthenticationRequest(clientInitMsg.Request, clientPAKEShare.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "get mutual auth request")
	}

	s.connState.request = request

	response, err := ProtocolMessageFromBody(&ServerResponseMsg{
		ExpAuth: ea,
		Request: request,
	})
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (s *Server) getAuthenticator(oprf1, userID []byte,
	clientRequest expauth.ExportedAuthenticatorRequest) (*expauth.ExportedAuthenticator, error) {
	cert := []*opaque.CertificateOPAQUESign{opaque.NewCertificateOPAQUESign(s.connState.opaqueServer.Config.Signer)}
	exts := mint.ExtensionList{}

	request := &opaque.CredentialRequest{
		UserID:   userID,
		OprfData: oprf1,
	}

	credResponse, err := s.connState.opaqueServer.CreateCredentialResponse(request)
	if err != nil {
		return nil, errors.Wrapf(err, "opaque: create cred response")
	}

	err = exts.Add(&opaque.PAKEServerAuthExtension{
		PAKEShare: &opaque.PAKEShareServer{
			ServerID: []byte(s.connState.opaqueServer.Config.ServerID),
			OprfMsg:  credResponse.OprfData,
			Envelope: credResponse.Envelope,
		},
		OPAQUEType: opaque.OPAQUESign,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "add pake server auth ext")
	}

	ea, err := s.connState.eaState.Authenticate(cert, exts, clientRequest)
	if err != nil {
		return nil, errors.Wrapf(err, "expauth: authenticate")
	}

	return ea, nil
}

func (s *Server) getMutualAuthenticationRequest(clientRequest expauth.ExportedAuthenticatorRequest,
	userID []byte) (expauth.ExportedAuthenticatorRequest, error) {
	reqExts := mint.ExtensionList{}

	supportedSchemes, err := clientRequest.SupportedSignatureSchemes()
	if err != nil {
		return nil, err
	}

	supportedSchemesExt := &mint.SignatureAlgorithmsExtension{Algorithms: supportedSchemes}

	err = reqExts.Add(supportedSchemesExt)
	if err != nil {
		return nil, err
	}

	err = reqExts.Add(&opaque.PAKEClientAuthExtension{UserID: userID})
	if err != nil {
		return nil, err
	}

	request, err := s.connState.eaState.Request(reqExts)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// VerifyAndRespond takes in the server message and returns the client response.
// Errors if the server message is invalid.
// TODO: make mutual auth optional.
func (c *Client) VerifyAndRespond(serverResponse *ProtocolMessage) (*ProtocolMessage, error) {
	protocolMessageBody, err := serverResponse.ToBody()
	if err != nil {
		return nil, err
	}

	serverResponseMsg, ok := protocolMessageBody.(*ServerResponseMsg)
	if !ok {
		return nil, common.ErrorUnexpectedMessage
	}

	creds, err := c.decryptAndValidateEnvelope(serverResponseMsg.ExpAuth)
	if err != nil {
		return nil, err
	}

	serverPublicKey, ok := creds.Find(opaque.CredentialTypeServerPublicKey)
	if !ok {
		return nil, errors.Wrapf(common.ErrorNotFound, "server public key credential")
	}

	err = c.validateExpAuth(serverResponseMsg.ExpAuth, serverPublicKey)
	if err != nil {
		return nil, err
	}

	var protocolMessage *ProtocolMessage

	if serverResponseMsg.Request != nil {
		userPrivateKey, ok := creds.Find(opaque.CredentialTypeUserPrivateKey)
		if !ok {
			return nil, errors.Wrapf(common.ErrorNotFound, "user private key credential")
		}

		crm, err := c.mutualAuthResponse(serverResponseMsg.Request, userPrivateKey.(crypto.Signer))
		if err != nil {
			return nil, err
		}

		protocolMessage, err = ProtocolMessageFromBody(crm)
		if err != nil {
			return nil, err
		}
	}

	return protocolMessage, nil
}

func (c *Client) decryptAndValidateEnvelope(expAuth *expauth.ExportedAuthenticator) (*opaque.Credentials, error) {
	serverPAKEShare, err := c.extractServerPAKEShare(expAuth)
	if err != nil {
		return nil, err
	}

	response := &opaque.CredentialResponse{
		OprfData: serverPAKEShare.OprfMsg,
		Envelope: serverPAKEShare.Envelope,
	}

	creds, err := c.opaqueState.RecoverCredentials(response)
	if err != nil {
		return nil, err
	}

	// Check that decrypted ServerID matches claimed
	// serverID, ok := creds.Find(opaque.CredentialTypeServerIdentity)
	// if !ok {
	// 	return nil, errors.Wrapf(common.ErrorNotFound, "server id credential")
	// }

	// Disabled because server might be proxied
	// if strings.Compare(serverID.(string), string(serverPAKEShare.ServerID)) != 0 {
	// 	return nil, errors.Wrapf(common.ErrorUnexpectedData, "server id")
	// }

	// Check correctness of user public key
	userPrivateKey, ok := creds.Find(opaque.CredentialTypeUserPrivateKey)
	if !ok {
		return nil, errors.Wrapf(common.ErrorNotFound, "user private key credential")
	}

	if !c.validatePublicKey(userPrivateKey.(crypto.Signer).Public()) {
		return nil, errors.Wrapf(common.ErrorUnexpectedData, "user public key")
	}

	return creds, nil
}

func (c *Client) validateExpAuth(expAuth *expauth.ExportedAuthenticator, serverPublicKey crypto.PublicKey) error {
	expAuth.SetPublicKey(serverPublicKey)

	_, _, err := c.eaState.Validate(expAuth, c.request)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) mutualAuthResponse(request expauth.ExportedAuthenticatorRequest, signer crypto.Signer) (*ClientResponseMsg, error) {
	// Check that the request contains a PCAE which contains the correct UserID
	pcae, err := c.extractPCAE(request)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(c.opaqueState.UserID, pcae.UserID) {
		return nil, errors.Wrapf(common.ErrorUnexpectedData, "expected %v, got %v", c.opaqueState.UserID, pcae.UserID)
	}

	// Construct EA signed with decrypted key pair
	cert := []*opaque.CertificateOPAQUESign{opaque.NewCertificateOPAQUESign(signer)}

	ea, err := c.eaState.Authenticate(cert, mint.ExtensionList{}, request)
	if err != nil {
		return nil, err
	}

	return &ClientResponseMsg{ExpAuth: ea}, nil
}

// Verify takes in the client response and the user password file and errors
// if the response is invalid.
func (s *Server) Verify(clientResponse *ProtocolMessage) error {
	protocolMessageBody, err := clientResponse.ToBody()
	if err != nil {
		return err
	}

	clientResponseMsg, ok := protocolMessageBody.(*ClientResponseMsg)
	if !ok {
		return common.ErrorUnexpectedMessage
	}

	// Verify EA
	clientResponseMsg.ExpAuth.SetPublicKey(s.connState.opaqueServer.UserRecord.UserPublicKey)

	_, _, err = s.connState.eaState.Validate(clientResponseMsg.ExpAuth, s.connState.request)
	if err != nil {
		return common.ErrorInvalidAuthenticator.Wrap(err)
	}

	return nil
}

func (s *Server) extractClientPAKEShare(request expauth.ExportedAuthenticatorRequest) (*opaque.PAKEShareClient, error) {
	psae, err := s.extractPSAE(request)
	if err != nil {
		return nil, err
	}

	psc, ok := psae.PAKEShare.(*opaque.PAKEShareClient)
	if !ok {
		return nil, errors.New("unexpected PAKE share type")
	}

	return psc, nil
}

func (s *Server) extractPSAE(request expauth.ExportedAuthenticatorRequest) (*opaque.PAKEServerAuthExtension, error) {
	psae := &opaque.PAKEServerAuthExtension{}

	err := psae.SetFromList(request.GetExtensions())
	if err != nil {
		return nil, err
	}

	return psae, nil
}

func (c *Client) extractServerPAKEShare(expAuth *expauth.ExportedAuthenticator) (*opaque.PAKEShareServer, error) {
	psae, err := c.extractPSAE(expAuth)
	if err != nil {
		return nil, err
	}

	pss, ok := psae.PAKEShare.(*opaque.PAKEShareServer)
	if !ok {
		return nil, errors.New("unexpected PAKE share type")
	}

	return pss, nil
}

func (c *Client) extractPSAE(expAuth *expauth.ExportedAuthenticator) (*opaque.PAKEServerAuthExtension, error) {
	psae := &opaque.PAKEServerAuthExtension{}

	err := psae.SetFromList(expAuth.Extensions())
	if err != nil {
		return nil, err
	}

	return psae, nil
}

func (c *Client) extractPCAE(request expauth.ExportedAuthenticatorRequest) (*opaque.PAKEClientAuthExtension, error) {
	pcae := &opaque.PAKEClientAuthExtension{}

	err := pcae.SetFromList(request.GetExtensions())
	if err != nil {
		return nil, err
	}

	return pcae, nil
}
