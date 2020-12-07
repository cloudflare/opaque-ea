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
	"crypto/sha256"

	"github.com/cloudflare/circl/oprf"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

// blind returns OPRF_1 (client OPRF msg) and remembers randomness used to generate it.
func (c *Client) blind(password string) ([]byte, error) {
	blind := [][]byte{}
	blind = append(blind, []byte(password))
	cRequest, err := c.oprfState.Request(blind)
	if err != nil {
		return nil, err
	}

	c.oprf1 = cRequest

	return cRequest.BlindedElements[0], nil
}

// evaluate returns OPRF_2 (server OPRF msg).
func (s *Server) evaluate(clientMessage []byte) ([]byte, error) {
	var blinded [][]byte
	blinded = append(blinded, []byte(clientMessage))

	evaluation, err := s.UserRecord.OprfState.Evaluate(blinded)
	if err != nil {
		return nil, err
	}

	return evaluation.Elements[0], nil
}

// finalizeHarden returns RwdPass (randomized password).
func (c *Client) finalizeHarden(serverMessage []byte) ([]byte, error) {
	var element [][]byte
	element = append(element, []byte(serverMessage))

	eval := &oprf.Evaluation{Elements: element}
	rwd, err := c.oprfState.Finalize(c.oprf1, eval, []byte("OPAQUE00"))
	if err != nil {
		return nil, err
	}

	// Harden the rwd.
	// "We note that the salt value typically input into the KDF can be set to a
	// constant, e.g., all zeros."
	OPAQUEPBKDFOutLength := int(32)
	OPAQUEPBKDFIters := int(4096)
	salt := []byte{0, 0, 0, 0}
	hardenedRwd := pbkdf2.Key(rwd[0], salt, OPAQUEPBKDFIters, OPAQUEPBKDFOutLength, sha256.New)

	rwdU := hkdf.Extract(sha256.New, hardenedRwd, []byte("rwdU"))

	return rwdU, nil
}
