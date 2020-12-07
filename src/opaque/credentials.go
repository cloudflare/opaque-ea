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

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint/syntax"
)

// CredentialType indicates the type of an OPAQUE credential extension struct.
// enum {
// 	skU(1),
// 	pkU(2),
// 	pkS(3),
// 	idU(4),
// 	idS(5),
// 	(255)
//   } CredentialType;
type CredentialType byte

// Credential types.
const (
	CredentialTypeUserPrivateKey CredentialType = 1 + iota
	CredentialTypeUserPublicKey
	CredentialTypeServerPublicKey
	CredentialTypeUserIdentity
	CredentialTypeServerIdentity
)

// A CredentialExtension is a piece of data that may be included in client Credentials.
//
//  struct {
// 	 CredentialType type;
// 	 CredentialData data<0..2^16-1>;
//  } CredentialExtension;
//
//      1            2
// | credType | credDataLen | credData |.
type CredentialExtension struct {
	CredentialType CredentialType
	CredentialData []byte `tls:"head=2"`
}

// Marshal returns the raw form of the struct.
func (ce *CredentialExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(ce)
}

// Unmarshal puts raw data into fields of a struct.
func (ce *CredentialExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ce)
}

func newCredentialExtension(t CredentialType, val interface{}) (*CredentialExtension, error) {
	var data []byte
	var err error
	var ok bool

	switch t {
	case CredentialTypeServerIdentity, CredentialTypeUserIdentity:
		data, ok = val.([]byte)
		if !ok {
			return nil, errors.New("expected array of bytes")
		}
	case CredentialTypeServerPublicKey, CredentialTypeUserPublicKey:
		data, err = x509.MarshalPKIXPublicKey(val)
		if err != nil {
			return nil, err
		}
	case CredentialTypeUserPrivateKey:
		data, err = x509.MarshalPKCS8PrivateKey(val)
		if err != nil {
			return nil, err
		}
	}

	return &CredentialExtension{
		CredentialType: t,
		CredentialData: data,
	}, nil
}

func (ce *CredentialExtension) parseToValue(t CredentialType) (interface{}, error) {
	if t != ce.CredentialType {
		return nil, errors.New("incorrect credential type")
	}

	switch t {
	case CredentialTypeServerIdentity, CredentialTypeUserIdentity:
		return string(ce.CredentialData), nil
	case CredentialTypeServerPublicKey, CredentialTypeUserPublicKey:
		val, err := x509.ParsePKIXPublicKey(ce.CredentialData)
		if err != nil {
			return nil, err
		}

		return val, nil
	case CredentialTypeUserPrivateKey:
		val, err := x509.ParsePKCS8PrivateKey(ce.CredentialData)
		if err != nil {
			return nil, err
		}

		signer, ok := val.(crypto.Signer)
		if !ok {
			return nil, errors.New("credential data is not a Signer")
		}

		return signer, nil
	}

	return nil, errors.New("unrecognized credential type")
}

// Credentials holds the decrypted user-specific envelope contents.
//
// struct {
// 	CredentialExtension secret_credentials<1..2^16-1>;
// 	CredentialExtension cleartext_credentials<0..2^16-1>;
// } Credentials;
//
//             2                              2
//  | secretCredsLen | secretCreds | cleartextCredsLen | cleartextCreds |
// SecretCredentials MUST contain the skU. It can contain the pkS.
// CleartextCredentials MUST contain the pkS
type Credentials struct {
	SecretCredentials    CredentialExtensionList `tls:"head=2,min=1"`
	CleartextCredentials CredentialExtensionList `tls:"head=2"`
}

// Find returns the value of credential type t in this Credentials struct, or
// false if not present.
func (creds *Credentials) Find(t CredentialType) (interface{}, bool) {
	if val, ok := creds.SecretCredentials.Find(t); ok {
		return val, true
	}

	if val, ok := creds.CleartextCredentials.Find(t); ok {
		return val, true
	}

	return nil, false
}

// Marshal returns the raw form of the struct.
func (creds *Credentials) Marshal() ([]byte, error) {
	return syntax.Marshal(creds)
}

// MarshalSplit encodes the Credential into its secret and clear parts.
func (creds *Credentials) MarshalSplit() (secret, cleartext []byte, err error) {
	secret, err = creds.SecretCredentials.Marshal()
	if err != nil {
		return nil, nil, err
	}

	cleartext, err = creds.CleartextCredentials.Marshal()

	return secret, cleartext, err
}

// Unmarshal puts raw data into fields of a struct.
func (creds *Credentials) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, creds)
}

// UnmarshalSplit decodes the Credential into its secret and clear parts.
func (creds *Credentials) UnmarshalSplit(secret, cleartext []byte) (int, error) {
	return creds.Unmarshal(append(secret, cleartext...))
}

// CredentialExtensionList is a list of credential extensions.
// Used to package secret and cleartext credentials separately.
type CredentialExtensionList []*CredentialExtension

type credentialExtensionListInner struct {
	List []*CredentialExtension `tls:"head=2"`
}

// Find returns the value of credential type t in this CredentialExtensionList, or
// false if not present.
func (cel CredentialExtensionList) Find(t CredentialType) (interface{}, bool) {
	for _, ext := range cel {
		if val, err := ext.parseToValue(t); err == nil {
			return val, true
		}
	}

	return nil, false
}

// Marshal encodes the Credential Extension List.
func (cel CredentialExtensionList) Marshal() ([]byte, error) {
	return syntax.Marshal(credentialExtensionListInner{List: cel})
}

// EncryptCredentials encrypts the given Credentials
// under a key derived from rwd, the randomized password.
func EncryptCredentials(rwd []byte, creds *Credentials, nonceLength int) (*Envelope, []byte, error) {
	nonce := common.GetRandomBytes(nonceLength)

	plaintext, authData, err := creds.MarshalSplit()
	if err != nil {
		return nil, nil, err
	}

	otp, err := NewAuthenticatedOneTimePad(rwd, nonce, len(plaintext))
	if err != nil {
		return nil, nil, err
	}

	ciphertext, tag, err := otp.Seal(plaintext, authData)
	if err != nil {
		return nil, nil, err
	}

	return &Envelope{
		Nonce:              nonce,
		EncryptedCreds:     ciphertext,
		AuthenticatedCreds: authData,
		AuthTag:            tag,
	}, otp.exporterKey, nil
}

// DecryptCredentials decrypts the encrypted envelope.
// Returns the decrypted Credentials struct, or an error if decryption fails.
func DecryptCredentials(rwd []byte, envelope *Envelope) (*Credentials, error) {
	otp, err := NewAuthenticatedOneTimePad(rwd, envelope.Nonce, len(envelope.EncryptedCreds))
	if err != nil {
		return nil, err
	}

	plaintext, err := otp.Open(envelope.EncryptedCreds, envelope.AuthenticatedCreds, envelope.AuthTag)
	if err != nil {
		return nil, err
	}

	// Make credentials
	creds := &Credentials{}
	_, err = creds.UnmarshalSplit(plaintext, envelope.AuthenticatedCreds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}
