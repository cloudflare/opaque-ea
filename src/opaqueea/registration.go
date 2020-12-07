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

	"github.com/cloudflare/opaque-ea/src/opaque"
)

// RegistrationRequest creates a registration request.
func (c *Client) RegistrationRequest(password string, key crypto.Signer) (*ProtocolMessage, error) {
	requestBody, err := c.opaqueState.CreateRegistrationRequest(password, key)
	if err != nil {
		return nil, err
	}

	request, err := ProtocolMessageFromBody(requestBody)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// RegistrationResponse creates a registration response.
func (s *Server) RegistrationResponse(registrationRequest *ProtocolMessage) (*ProtocolMessage, error) {
	requestBody, err := registrationRequest.ToBody()
	if err != nil {
		return nil, err
	}

	responseBody, err := s.connState.opaqueServer.CreateRegistrationResponse(requestBody.(*opaque.RegistrationRequest))
	if err != nil {
		return nil, err
	}

	response, err := ProtocolMessageFromBody(responseBody)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// FinalizeRegistration creates a finalize registration.
func (c *Client) FinalizeRegistration(response *ProtocolMessage) (*ProtocolMessage, error) {
	responseBody, err := response.ToBody()
	if err != nil {
		return nil, err
	}

	uploadBody, _, err := c.opaqueState.FinalizeRegistrationRequest(responseBody.(*opaque.RegistrationResponse))
	if err != nil {
		return nil, err
	}

	upload, err := ProtocolMessageFromBody(uploadBody)
	if err != nil {
		return nil, err
	}

	return upload, nil
}

// UploadCredentials uploads the credentials.
func (s *Server) UploadCredentials(registrationUpload *ProtocolMessage) error {
	uploadBody, err := registrationUpload.ToBody()
	if err != nil {
		return err
	}

	return s.connState.opaqueServer.StoreUserRecord(uploadBody.(*opaque.RegistrationUpload))
}
