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
	"github.com/cloudflare/opaque-ea/src/common"
)

// CreateCredentialRequest is called by the client on a password to initiate the
// online OPAQUE protocol.
// Returns a credential request, which will be sent to the server.
func (c *Client) CreateCredentialRequest(password []byte) (*CredentialRequest, error) {
	blinded, err := c.blind(string(password))
	if err != nil {
		return nil, err
	}

	return &CredentialRequest{
		UserID:   c.UserID,
		OprfData: blinded,
	}, nil
}

// CreateCredentialResponse is called by the server on receiving a request from
// the client.
// Returns a credential response, which will be sent to the server.
func (s *Server) CreateCredentialResponse(request *CredentialRequest) (*CredentialResponse, error) {
	record, err := s.GetUserRecordFromUsername(request.UserID)
	if err != nil {
		return nil, err
	}

	s.UserRecord = record
	eval, err := s.evaluate(request.OprfData)
	if err != nil {
		s.UserRecord = nil
		return nil, err
	}

	return &CredentialResponse{
		OprfData:        eval,
		Envelope:        record.Envelope,
		serverPublicKey: s.Config.Signer.Public(),
	}, nil
}

// RecoverCredentials is called by the client on receiving an OPAQUE response from
// the server.
// Returns the credentials that the client uploaded during the registration phase.
func (c *Client) RecoverCredentials(response *CredentialResponse) (*Credentials, error) {
	rwd, err := c.finalizeHarden(response.OprfData)
	if err != nil {
		return nil, err
	}

	creds, err := DecryptCredentials(rwd, response.Envelope)
	if err != nil {
		return nil, common.ErrorBadEnvelope.Wrap(err)
	}

	return creds, nil
}
