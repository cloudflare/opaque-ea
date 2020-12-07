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
	"math/big"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint/syntax"
)

// ProtocolMessageType indicates the OPAQUE protocol message type
//
// enum {
// 	registration_request(1),
// 	registration_response(2),
// 	registration_upload(3),
// 	credential_request(4),
// 	credential_response(5),
// 	(255)
// } ProtocolMessageType;.
type ProtocolMessageType byte

// OPAQUE protocol message types.
const (
	ProtocolMessageTypeRegistrationRequest ProtocolMessageType = 1 + iota
	ProtocolMessageTypeRegistrationResponse
	ProtocolMessageTypeRegistrationUpload
	ProtocolMessageTypeCredentialRequest
	ProtocolMessageTypeCredentialResponse
)

// A ProtocolMessage is a bundle containing all OPAQUE data sent in a flow
// between parties (during registration or login).
//
// struct {
// 	ProtocolMessageType msg_type;    /* protocol message type */
// 	uint24 length;                   /* remaining bytes in message */
// 	select (ProtocolMessage.msg_type) {
// 		case registration_request: RegistrationRequest;
// 		case registration_response: RegistrationResponse;
// 		case registration_upload: RegistrationUpload;
// 		case credential_request: CredentialRequest;
// 		case credential_response: CredentialResponse;
// 	};
// } ProtocolMessage;
//
//        1               3
// | messageType | messageBodyLen | messageBody |
type ProtocolMessage struct {
	MessageType    ProtocolMessageType
	MessageBodyRaw []byte `tls:"head=3"`
}

// Marshal encodes a ProtocolMessage.
func (msg *ProtocolMessage) Marshal() ([]byte, error) {
	return syntax.Marshal(msg)
}

// Unmarshal decodes a ProtocolMessage.
func (msg *ProtocolMessage) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, msg)
}

// ToBody assigns the message type.
func (msg *ProtocolMessage) ToBody() (ProtocolMessageBody, error) {
	var body ProtocolMessageBody

	switch msg.MessageType {
	case ProtocolMessageTypeRegistrationRequest:
		body = new(RegistrationRequest)
	case ProtocolMessageTypeRegistrationResponse:
		body = new(RegistrationResponse)
	case ProtocolMessageTypeRegistrationUpload:
		body = new(RegistrationUpload)
	case ProtocolMessageTypeCredentialRequest:
		body = new(CredentialRequest)
	case ProtocolMessageTypeCredentialResponse:
		body = new(CredentialResponse)
	default:
		return body, errors.Wrapf(common.ErrorUnrecognizedMessage, "message type %s", msg.MessageType)
	}

	return body, nil
}

// ProtocolMessageFromBody reconstructs a ProtocolMessage from its body.
func ProtocolMessageFromBody(body ProtocolMessageBody) (*ProtocolMessage, error) {
	bodyRaw, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	return &ProtocolMessage{
		MessageType:    body.Type(),
		MessageBodyRaw: bodyRaw,
	}, nil
}

// ProtocolMessageBody is an interface implemented by all protocol messages.
// Represents the "inner" part of the message, not including metadata.
type ProtocolMessageBody interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) (int, error)
	Type() ProtocolMessageType
}

// A CredentialRequest is the first message sent by the client to initiate
// OPAQUE.
// Implements ProtocolMessageBody.
//
// struct {
// 	opaque id<0..2^16-1>;
// 	opaque data<1..2^16-1>;
// } CredentialRequest;
//
//        2                    2
// | userIDLen | userID | oprfDataLen | oprfData |
type CredentialRequest struct {
	UserID   []byte `tls:"head=2"`       // client account info, if present
	OprfData []byte `tls:"head=2,min=1"` // an encoded element in the OPRF group
}

var _ ProtocolMessageBody = (*CredentialRequest)(nil)

// Marshal returns the raw form of the struct.
func (cr *CredentialRequest) Marshal() ([]byte, error) {
	return syntax.Marshal(cr)
}

// Unmarshal puts raw data into fields of a struct.
func (cr *CredentialRequest) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cr)
}

// Type returns the type of this struct.
func (*CredentialRequest) Type() ProtocolMessageType {
	return ProtocolMessageTypeCredentialRequest
}

// A CredentialResponse is the message sent by the server in response to
// the Client's initial OPAQUE message.
// Implements ProtocolMessageBody.
//
// struct {
// 	opaque data<1..2^16-1>;
// 	opaque envelope<1..2^16-1>;
// 	opaque pkS<0..2^16-1;
// } CredentialResponse;
//
//        2                                2
// | oprfDataLen | oprfData | envelope | pkSLen | pkS |
type CredentialResponse struct {
	OprfData        []byte           // an encoded element in the OPRF group
	Envelope        *Envelope        // an authenticated encoding of a Credentials structure
	serverPublicKey crypto.PublicKey // OPTIONAL: an encoded public key that will be used for the online authenticated key exchange stage.
}

// Type returns the type of this struct.
func (*CredentialResponse) Type() ProtocolMessageType {
	return ProtocolMessageTypeCredentialResponse
}

type credentialResponseInner struct {
	OprfData        []byte `tls:"head=2,min=1"`
	Envelope        *Envelope
	ServerPublicKey []byte `tls:"head=2"`
}

// Marshal encodes a Credential Response.
func (cr *CredentialResponse) Marshal() ([]byte, error) {
	rawPublicKey, err := x509.MarshalPKIXPublicKey(cr.serverPublicKey)
	if err != nil {
		return nil, err
	}

	toMarshal := &credentialResponseInner{
		cr.OprfData,
		cr.Envelope,
		rawPublicKey,
	}

	return syntax.Marshal(toMarshal)
}

// Unmarshal decodes a Credential Response.
func (cr *CredentialResponse) Unmarshal(data []byte) (int, error) {
	cri := new(credentialResponseInner)

	bytesRead, err := syntax.Unmarshal(data, cri)
	if err != nil {
		return 0, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(cri.ServerPublicKey)
	if err != nil {
		return 0, err
	}

	*cr = CredentialResponse{
		cri.OprfData, cri.Envelope, publicKey,
	}

	return bytesRead, nil
}

// RequestMetadata is the secret state generated and held by the client
// during the OPAQUE protocol. Should be deleted after the protocol completes.
//
// struct {
// 	opaque data_blind<1..2^16-1>;
// } RequestMetadata;.
type RequestMetadata struct {
	Blind *big.Int // an oprf scalar element (randomness used to blind OPRF1)
}
