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
	"crypto"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
)

// CreateRegistrationRequest is called by the client to create the first OPAQUE registration message
// Errors if the OPRF message cannot be created. e.g, if this client instance has already
// been used to run an OPRF.
func (c *Client) CreateRegistrationRequest(password string, key crypto.Signer) (*RegistrationRequest, error) {
	c.signer = key

	blinded, err := c.blind(password)
	if err != nil {
		return nil, err
	}

	return &RegistrationRequest{
		UserID:   c.UserID,
		OprfData: blinded,
	}, nil
}

// CreateRegistrationResponse is called by the server to respond to a OPAQUE registration request
// from a client.
// It fails is an OPRF message cannot be created.
func (s *Server) CreateRegistrationResponse(msg *RegistrationRequest) (*RegistrationResponse, error) {
	oprfServer, err := oprf.NewServer(s.Config.Suite, nil)
	if err != nil {
		return nil, err
	}

	s.UserRecord.OprfState = oprfServer
	eval, err := s.evaluate(msg.OprfData)
	if err != nil {
		s.UserRecord.OprfState = nil
		return nil, err
	}

	if err := s.SetUserID(msg.UserID); err != nil {
		s.UserRecord.OprfState = nil
		return nil, err
	}

	return &RegistrationResponse{
		OprfData:                 eval,
		ServerPublicKey:          s.Config.Signer.Public(),
		CredentialEncodingPolicy: s.Config.CredentialEncodingPolicy,
	}, nil
}

// FinalizeRegistrationRequest is called by the client to respond to the server's response
// to its registration request (registration response).
// Returns a registration upload message and an exporter key.
// Errors if the OPRF cannot be completed or there is a problem encrypting the
// envelope.
func (c *Client) FinalizeRegistrationRequest(msg *RegistrationResponse) (*RegistrationUpload, []byte, error) {
	rwd, err := c.finalizeHarden(msg.OprfData)
	if err != nil {
		return nil, nil, err
	}

	creds, err := c.credentialsFromPolicy(msg.CredentialEncodingPolicy, msg.ServerPublicKey)
	if err != nil {
		return nil, nil, err
	}

	// a fresh random nonce Nonce of length LH, where LH is the
	// output length in bytes of the hash function underlying HKDF.
	// OPRFP256 hash function is SHA256.
	nonceLen := int(32)
	envelope, exporterKey, err := EncryptCredentials(rwd, creds, nonceLen)
	if err != nil {
		return nil, nil, err
	}

	return &RegistrationUpload{
		Envelope:      envelope,
		UserPublicKey: c.signer.Public(),
	}, exporterKey, nil
}

func (c *Client) credentialsFromPolicy(policy *CredentialEncodingPolicy,
	serverPublicKey crypto.PublicKey) (*Credentials, error) {
	secretCreds := make(CredentialExtensionList, len(policy.SecretTypes))
	cleartextCreds := make(CredentialExtensionList, len(policy.CleartextTypes))

	for i, credType := range policy.SecretTypes {
		cred, err := c.getCredentialFromType(credType, serverPublicKey)
		if err != nil {
			return nil, err
		}

		secretCreds[i] = cred
	}

	for i, credType := range policy.CleartextTypes {
		if credType == CredentialTypeUserPrivateKey {
			return nil, common.ErrorForbiddenPolicy
		}

		cred, err := c.getCredentialFromType(credType, serverPublicKey)
		if err != nil {
			return nil, err
		}

		cleartextCreds[i] = cred
	}

	return &Credentials{
		SecretCredentials:    secretCreds,
		CleartextCredentials: cleartextCreds,
	}, nil
}

func (c *Client) getCredentialFromType(t CredentialType, serverPublicKey crypto.PublicKey) (*CredentialExtension, error) {
	var val interface{}

	switch t {
	case CredentialTypeServerIdentity:
		val = c.ServerID
	case CredentialTypeUserIdentity:
		val = c.UserID
	case CredentialTypeServerPublicKey:
		val = serverPublicKey
	case CredentialTypeUserPublicKey:
		val = c.signer.Public()
	case CredentialTypeUserPrivateKey:
		val = c.signer
	}

	cred, err := newCredentialExtension(t, val)
	if err != nil {
		return nil, err
	}

	return cred, nil
}

// StoreUserRecord is called by the Server to add the new client identity
// to it's records, ending the registration step.
// Errors if the record cannot be added, e.g. because the username has already
// been registered.
func (s *Server) StoreUserRecord(msg *RegistrationUpload) error {
	record, err := s.InsertNewUserRecord(msg.UserPublicKey, msg.Envelope)

	s.UserRecord = record

	return err
}
