// Copyright (c) 2020, Cloudflare. All rights reserved.
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
	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
)

// ProtocolMessage is a wrap around an OPAQUE protocol message.
type ProtocolMessage opaque.ProtocolMessage // renaming so we can define new methods

// OPAQUE-EA protocol message types.
const (
	ProtocolMessageTypeClientRequest opaque.ProtocolMessageType = 6 + iota // start where OPAQUE left off
	ProtocolMessageTypeClientResponse
	ProtocolMessageTypeServerResponse
)

// ClientInitMsg is the first message sent by a client in the OPAQUE-EA flow.
// Contains an exported authenticator request with the PAKEServerAuth
// extension.
type ClientInitMsg struct {
	Request expauth.ExportedAuthenticatorRequest
}

var _ opaque.ProtocolMessageBody = (*ClientInitMsg)(nil)

// Marshal returns the raw form of the struct.
func (cim *ClientInitMsg) Marshal() ([]byte, error) {
	return cim.Request.Marshal()
}

// Unmarshal puts raw data into fields of a struct and returns the number of
// bytes read.
func (cim *ClientInitMsg) Unmarshal(data []byte) (int, error) {
	request := &expauth.ClientExportedAuthenticatorRequest{}

	bytesRead, err := request.Unmarshal(data)
	if err != nil {
		return 0, err
	}

	cim.Request = request

	return bytesRead, nil
}

// Type returns the type of this ProtocolMessageBody.
func (cim *ClientInitMsg) Type() opaque.ProtocolMessageType {
	return ProtocolMessageTypeClientRequest
}

// ClientResponseMsg is the second message sent by the client in the OPAQUE-EA
// flow. It is only sent if the Server requests mutual authentication.
// It contains a single Exported Authenticator from the Client.
type ClientResponseMsg struct {
	ExpAuth *expauth.ExportedAuthenticator
}

var _ opaque.ProtocolMessageBody = (*ClientResponseMsg)(nil)

// Marshal returns the raw form of the struct.
func (cr *ClientResponseMsg) Marshal() ([]byte, error) {
	return cr.ExpAuth.Marshal()
}

// Unmarshal puts raw data into fields of a struct and returns the number of
// bytes read.
func (cr *ClientResponseMsg) Unmarshal(data []byte) (int, error) {
	ea := &expauth.ExportedAuthenticator{}

	bytesRead, err := ea.Unmarshal(data)
	if err != nil {
		return 0, err
	}

	cr.ExpAuth = ea

	return bytesRead, nil
}

// Type returns the type of this ProtocolMessageBody.
func (cr *ClientResponseMsg) Type() opaque.ProtocolMessageType {
	return ProtocolMessageTypeClientResponse
}

// ServerResponseMsg is the first message sent by the server in response to the
// client's initial message in the OPAQUE-EA flow.
// It contains an Exported Authenticator from the Server containing a
// PAKEServerAuth extension.
// This message also contains an EA request from the Server to the Client with a
// PAKEClientAuth extension.
// TODO: make mutual auth optional.
type ServerResponseMsg struct {
	ExpAuth *expauth.ExportedAuthenticator       // exp auth from server to client
	Request expauth.ExportedAuthenticatorRequest // request from server to client (optional mutual auth)
}

var _ opaque.ProtocolMessageBody = (*ServerResponseMsg)(nil)

// Marshal returns the raw form of the struct.
func (srm *ServerResponseMsg) Marshal() ([]byte, error) {
	toMarshal := []common.Marshaler{srm.ExpAuth, srm.Request}
	return common.MarshalList(toMarshal)
}

// Unmarshal puts raw data into fields of a struct and returns the number of
// bytes read.
func (srm *ServerResponseMsg) Unmarshal(data []byte) (int, error) {
	ea := &expauth.ExportedAuthenticator{}
	req := &expauth.ServerExportedAuthenticatorRequest{}
	toUnmarshal := []common.Unmarshaler{ea, req}

	bytesRead, err := common.UnmarshalList(toUnmarshal, data)
	if err != nil {
		return 0, err
	}

	srm.ExpAuth = ea
	srm.Request = req

	return bytesRead, nil
}

// Type returns the type of this ProtocolMessageBody.
func (srm *ServerResponseMsg) Type() opaque.ProtocolMessageType {
	return ProtocolMessageTypeServerResponse
}

// Marshal marshals a protocol message.
func (pm *ProtocolMessage) Marshal() ([]byte, error) {
	return (*opaque.ProtocolMessage)(pm).Marshal()
}

// Unmarshal unmarshals a protocol message.
func (pm *ProtocolMessage) Unmarshal(data []byte) (int, error) {
	return (*opaque.ProtocolMessage)(pm).Unmarshal(data)
}

// ToBody gets the body of a protocol message.
func (pm *ProtocolMessage) ToBody() (opaque.ProtocolMessageBody, error) {
	body, err := (*opaque.ProtocolMessage)(pm).ToBody()
	if err != nil { // if type not recognized by opaque package
		switch pm.MessageType {
		case ProtocolMessageTypeClientRequest:
			body = new(ClientInitMsg)
		case ProtocolMessageTypeClientResponse:
			body = new(ClientResponseMsg)
		case ProtocolMessageTypeServerResponse:
			body = new(ServerResponseMsg)
		default:
			return body, err
		}
	}

	_, err = body.Unmarshal(pm.MessageBodyRaw)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// ProtocolMessageFromBody creates a protocol message from its body.
func ProtocolMessageFromBody(body opaque.ProtocolMessageBody) (*ProtocolMessage, error) {
	pm, err := opaque.ProtocolMessageFromBody(body)
	if err != nil {
		return nil, err
	}

	return (*ProtocolMessage)(pm), nil
}
