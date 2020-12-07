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

package expauth

import (
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
	"github.com/tatianab/mint/syntax"
)

// TLSMessage is a wrapper for mint HandshakeMessageBody
// Similar to mint's HandshakeMessage but without DTLS info,
// and allows us to use mint/syntax marshal/unmarshal functionality.
type TLSMessage struct {
	MessageType    mint.HandshakeType
	MessageBodyRaw []byte `tls:"head=3"`
}

// Marshal marshals a TLS Message.
func (msg *TLSMessage) Marshal() ([]byte, error) {
	return syntax.Marshal(msg)
}

// Unmarshal unmarshals a TLS Message.
func (msg *TLSMessage) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, msg)
}

// ToBody returns the body of a TLS Message.
func (msg *TLSMessage) ToBody() (mint.HandshakeMessageBody, error) {
	var body mint.HandshakeMessageBody

	switch msg.MessageType {
	case mint.HandshakeTypeCertificate:
		body = new(mint.CertificateBody)
	case mint.HandshakeTypeCertificateVerify:
		body = new(mint.CertificateVerifyBody)
	case mint.HandshakeTypeFinished:
		body = &mint.FinishedBody{VerifyDataLen: len(msg.MessageBodyRaw)}
	default:
		return body, errors.New("unrecognized TLS message")
	}

	_, err := body.Unmarshal(msg.MessageBodyRaw)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// TLSMessageFromBody returns a TLS Message from a body.
func TLSMessageFromBody(body mint.HandshakeMessageBody) (*TLSMessage, error) {
	data, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	m := &TLSMessage{
		MessageType:    body.Type(),
		MessageBodyRaw: data,
	}

	return m, nil
}
