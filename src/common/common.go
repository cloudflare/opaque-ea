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

package common

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"

	"github.com/pkg/errors"

	"github.com/tatianab/mint"
	"golang.org/x/crypto/cryptobyte"
)

// GetRandomBytes returns n random bytes.
func GetRandomBytes(n int) []byte {
	var key []byte
	for success := false; !success; {
		key = make([]byte, n)
		if _, err := rand.Read(key); err != nil {
			continue
		}

		success = true
	}

	return key
}

// Marshaler is the interface implemented by types that can be marshaled
// (converted to raw bytes).
type Marshaler interface {
	Marshal() ([]byte, error)
}

// MarshalList marshals a list of values that are marshal-able.
func MarshalList(toMarshal []Marshaler) ([]byte, error) {
	var b cryptobyte.Builder

	for _, tm := range toMarshal {
		if tm != nil {
			raw, err := tm.Marshal()
			if err != nil {
				return nil, err
			}

			b.AddBytes(raw)
		}
	}

	return b.BytesOrPanic(), nil
}

// Unmarshaler is the interface implemented by types that can be unmarshaled
// (converted from raw bytes to a struct).
type Unmarshaler interface {
	Unmarshal([]byte) (int, error)
}

// UnmarshalList unmarshals a list of values that are unmarshal-able.
func UnmarshalList(toUnmarshal []Unmarshaler, data []byte) (int, error) {
	totalBytes := 0

	for _, tu := range toUnmarshal {
		bytesRead, err := tu.Unmarshal(data[totalBytes:])
		if err != nil {
			return 0, err
		}

		totalBytes += bytesRead
	}

	return totalBytes, nil
}

// MarshalUnmarshaler is a type that can marshal and unmarshal itself.
type MarshalUnmarshaler interface {
	Marshaler
	Unmarshaler
}

// SelfSignedCerts returns a list of self-signed certificates, each signed with
// a different signature scheme supported by mint.
func SelfSignedCerts(domain string, roots *x509.CertPool) ([]*mint.Certificate, error) {
	certs := make([]*mint.Certificate, len(MintSupportedSignatureSchemes))

	for i, s := range MintSupportedSignatureSchemes {
		cert, err := SelfSignedCert(domain, roots, s)
		if err != nil {
			return nil, err
		}

		certs[i] = cert
	}

	return certs, nil
}

// SelfSignedCert creates a new self-signed cert for the given domain and
// adds it to the roots pool (if provided).
func SelfSignedCert(domain string, roots *x509.CertPool, scheme mint.SignatureScheme) (*mint.Certificate, error) {
	// Make self signed certificate for testing
	privKey, x509cert, err := mint.MakeNewSelfSignedCert(domain, scheme)
	if err != nil {
		return nil, err
	}

	cert := &mint.Certificate{
		Chain:      []*x509.Certificate{x509cert},
		PrivateKey: privKey,
	}

	// set cert as roots
	if roots != nil {
		roots.AddCert(x509cert)
	}

	return cert, nil
}

// GetExtensionListFromSignatureScheme returns an ExtensionList containing the
// given signature scheme.
func GetExtensionListFromSignatureScheme(sigScheme mint.SignatureScheme) mint.ExtensionList {
	supportedSchemes := &mint.SignatureAlgorithmsExtension{Algorithms: []mint.SignatureScheme{sigScheme}}

	var extensions mint.ExtensionList

	err := extensions.Add(supportedSchemes)
	if err != nil {
		panic(err)
	}

	return extensions
}

// GetExtensionListFromSignatureSchemes returns an ExtensionList containing the
// given signature schemes.
func GetExtensionListFromSignatureSchemes(sigSchemes []mint.SignatureScheme) mint.ExtensionList {
	var extensions mint.ExtensionList

	supportedSchemes := &mint.SignatureAlgorithmsExtension{Algorithms: sigSchemes}

	err := extensions.Add(supportedSchemes)
	if err != nil {
		panic(err)
	}

	return extensions
}

// MintSupportedSignatureSchemes is a list of all signature schemes supported
// by the mint package.
var MintSupportedSignatureSchemes = []mint.SignatureScheme{
	mint.ECDSA_P256_SHA256, mint.ECDSA_P384_SHA384, mint.ECDSA_P521_SHA512,
	mint.RSA_PKCS1_SHA256, mint.RSA_PKCS1_SHA384, mint.RSA_PKCS1_SHA512,
}

// HashMap is a map from signature schemes to the hash that they use.
var HashMap = map[mint.SignatureScheme]crypto.Hash{
	mint.RSA_PKCS1_SHA1:    crypto.SHA1,
	mint.RSA_PKCS1_SHA256:  crypto.SHA256,
	mint.RSA_PKCS1_SHA384:  crypto.SHA384,
	mint.RSA_PKCS1_SHA512:  crypto.SHA512,
	mint.ECDSA_P256_SHA256: crypto.SHA256,
	mint.ECDSA_P384_SHA384: crypto.SHA384,
	mint.ECDSA_P521_SHA512: crypto.SHA512,
	mint.RSA_PSS_SHA256:    crypto.SHA256,
	mint.RSA_PSS_SHA384:    crypto.SHA384,
	mint.RSA_PSS_SHA512:    crypto.SHA512,
}

// XORBytes xors b into a. Byte slices a and b must be of equal length.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("XORBytes: byte slices must have equal length")
	}

	for i := 0; i < len(a); i++ {
		a[i] ^= b[i]
	}

	return a, nil
}
