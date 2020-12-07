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
	"github.com/tatianab/mint/syntax"
)

// Envelope is the data encrypted under the randomized password
// which is stored encrypted and sent to to the user.
//
// struct {
// 	opaque nonce[Nn];
// 	opaque ct<1..2^16-1>;
// 	opaque auth_data<0..2^16-1>;
// 	opaque auth_tag<1..2^16-1>;
// } Envelope;
//
//      1                   2                         2                         2
// | nonceLen | nonce | encCredsLen | encCreds | authCredsLen | authCreds | authTagLen | authTag |.
type Envelope struct {
	Nonce              []byte `tls:"head=1"`       // unique value, , which must be 32 byte long.
	EncryptedCreds     []byte `tls:"head=2,min=1"` // raw encrypted and authenticated credential extensions list.
	AuthenticatedCreds []byte `tls:"head=2"`       // raw authenticated credential extensions list.
	AuthTag            []byte `tls:"head=2,min=1"` // tag authenticating the envelope contents.
}

// Marshal returns the raw form of the struct.
func (e *Envelope) Marshal() ([]byte, error) {
	return syntax.Marshal(e)
}

// Unmarshal puts raw data into fields of a struct.
func (e *Envelope) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, e)
}
