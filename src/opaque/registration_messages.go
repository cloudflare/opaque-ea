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
	"crypto/x509"

	"github.com/tatianab/mint/syntax"
)

// RegistrationRequest is the first message sent by the client to
// register a new OPAQUE identity with that server
//
// struct {
// 	opaque id<0..2^16-1>;
// 	opaque data<1..2^16-1>;
// } RegistrationRequest;
//
//       2                     2
// | userIDLen | userID | oprfDataLen | oprfData |.
type RegistrationRequest struct {
	UserID   []byte `tls:"head=2"`
	OprfData []byte `tls:"head=2, min=1"`
}

// Marshal returns the raw form of this struct.
func (rr *RegistrationRequest) Marshal() ([]byte, error) {
	return syntax.Marshal(rr)
}

// Unmarshal converts the raw data into a struct and returns the number of
// bytes read.
func (rr *RegistrationRequest) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, rr)
}

// Type returns the type of this struct.
func (*RegistrationRequest) Type() ProtocolMessageType {
	return ProtocolMessageTypeRegistrationRequest
}

// RegistrationResponse is the first message sent by the Server in response
// to the client's registration request.
//
// struct {
// 	opaque data<0..2^16-1>;
// 	opaque pkS<0..2^16-1>;
// 	CredentialType secret_types<1..254>;
// 	CredentialType cleartext_types<0..254>;
// } RegistrationResponse;
//
//       2                       2                 1                                1
// | oprfDataLen | oprfData | pkSLen | pkS | secretTypesLen | secretTypes | cleartextTypesLen | cleartextTypes |.
type RegistrationResponse struct {
	OprfData                 []byte
	ServerPublicKey          crypto.PublicKey
	CredentialEncodingPolicy *CredentialEncodingPolicy
}

type registrationResponseInner struct {
	OprfData        []byte           `tls:"head=2"`
	ServerPublicKey []byte           `tls:"head=2"`
	SecretTypes     []CredentialType `tls:"head=1, min=1"`
	CleartextTypes  []CredentialType `tls:"head=1"`
}

// Marshal returns the raw form of this struct.
func (rr *RegistrationResponse) Marshal() ([]byte, error) {
	rawServerPublicKey, err := x509.MarshalPKIXPublicKey(rr.ServerPublicKey)
	if err != nil {
		return nil, err
	}

	inner := &registrationResponseInner{
		OprfData:        rr.OprfData,
		ServerPublicKey: rawServerPublicKey,
		SecretTypes:     rr.CredentialEncodingPolicy.SecretTypes,
		CleartextTypes:  rr.CredentialEncodingPolicy.CleartextTypes,
	}

	return syntax.Marshal(inner)
}

// Unmarshal converts the raw data into a struct and returns the number of
// bytes read.
func (rr *RegistrationResponse) Unmarshal(data []byte) (int, error) {
	inner := &registrationResponseInner{}

	bytesRead, err := syntax.Unmarshal(data, inner)
	if err != nil {
		return 0, err
	}

	serverPublicKey, err := x509.ParsePKIXPublicKey(inner.ServerPublicKey)
	if err != nil {
		return 0, err
	}

	*rr = RegistrationResponse{
		OprfData:        inner.OprfData,
		ServerPublicKey: serverPublicKey,
		CredentialEncodingPolicy: &CredentialEncodingPolicy{
			SecretTypes:    inner.SecretTypes,
			CleartextTypes: inner.CleartextTypes,
		},
	}

	return bytesRead, nil
}

// Type returns the type of this struct.
func (*RegistrationResponse) Type() ProtocolMessageType {
	return ProtocolMessageTypeRegistrationResponse
}

// RegistrationUpload is the second and final message sent by the
// client to register a new identity with a server.
//
// struct {
// 	Envelope envelope;
// 	opaque pkU<0..2^16-1>;
// } RegistrationUpload;
//
//                  2
// | envelope | pubKeyLen | pubKey.
type RegistrationUpload struct {
	Envelope      *Envelope
	UserPublicKey crypto.PublicKey
}

type registrationUploadInner struct {
	Envelope      *Envelope
	UserPublicKey []byte `tls:"head=2"`
}

// Marshal returns the raw form of this struct.
func (ru *RegistrationUpload) Marshal() ([]byte, error) {
	rawPublicKey, err := x509.MarshalPKIXPublicKey(ru.UserPublicKey)
	if err != nil {
		return nil, err
	}

	inner := &registrationUploadInner{
		Envelope:      ru.Envelope,
		UserPublicKey: rawPublicKey,
	}

	return syntax.Marshal(inner)
}

// Unmarshal converts the raw data into a struct and returns the number of
// bytes read.
func (ru *RegistrationUpload) Unmarshal(data []byte) (int, error) {
	inner := &registrationUploadInner{}

	bytesRead, err := syntax.Unmarshal(data, inner)
	if err != nil {
		return 0, err
	}

	userPublicKey, err := x509.ParsePKIXPublicKey(inner.UserPublicKey)
	if err != nil {
		return 0, err
	}

	*ru = RegistrationUpload{
		Envelope:      inner.Envelope,
		UserPublicKey: userPublicKey,
	}

	return bytesRead, nil
}

// Type returns the type of this struct.
func (*RegistrationUpload) Type() ProtocolMessageType {
	return ProtocolMessageTypeRegistrationUpload
}
