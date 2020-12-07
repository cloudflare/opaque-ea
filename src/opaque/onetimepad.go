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
	"crypto/hmac"
	"crypto/sha256"
	"hash"

	"github.com/cloudflare/opaque-ea/src/common"
	"golang.org/x/crypto/hkdf"
)

// AuthenticatedOneTimePad is a cipher for encrypting/decrypting OPAQUE
// credentials. It is specialized and should likely not be used elsewhere.
type AuthenticatedOneTimePad struct {
	nonce       []byte
	pad         []byte
	exporterKey []byte
	mac         hash.Hash
}

// NewAuthenticatedOneTimePad returns a new AOTP cipher initialized with
// the given key and nonce.
// It calculates:
// pseudorandom_pad = HKDF-Expand(rwdU, concat(nonce, "Pad"), len(pt))
// auth_key = HKDF-Expand(rwdU, concat(nonce, "AuthKey"), Nh)
// export_key = HKDF-Expand(rwdU, concat(nonce, "ExportKey"), Nh)
func NewAuthenticatedOneTimePad(key, nonce []byte, l int) (*AuthenticatedOneTimePad, error) {
	hash := sha256.New // should be the same as the OPRF suite

	pad := make([]byte, l)
	_, err := hkdf.Expand(hash, key, []byte("Pad")).Read(pad)
	if err != nil {
		panic(err)
	}

	authKey := make([]byte, 32)
	_, err = hkdf.Expand(hash, key, []byte("AuthKey")).Read(authKey)
	if err != nil {
		return nil, err
	}

	exporterKey := make([]byte, 32)
	_, err = hkdf.Expand(hash, key, []byte("ExportKey")).Read(exporterKey)
	if err != nil {
		return nil, err
	}

	return &AuthenticatedOneTimePad{
		nonce:       nonce,
		pad:         pad,
		exporterKey: exporterKey,
		mac:         hmac.New(hash, authKey),
	}, nil
}

// Seal encrypts and HMACs the given plaintext.
// MUST only be called once (it is a one-time pad after all).
// It calculates:
// Set Ct = SecEnv XOR Pad
// Set E = Nonce | Ct | authData
// Set T = HMAC(HmacKey, E)
func (otp *AuthenticatedOneTimePad) Seal(plaintext, authData []byte) (ciphertext, tag []byte, err error) {
	ciphertext, err = common.XORBytes(otp.pad, plaintext)
	if err != nil {
		return nil, nil, err
	}

	_, err = otp.mac.Write(otp.nonce)
	if err != nil {
		return nil, nil, err
	}

	_, err = otp.mac.Write(ciphertext)
	if err != nil {
		otp.mac.Reset()
		return nil, nil, err
	}

	_, err = otp.mac.Write(authData)
	if err != nil {
		otp.mac.Reset()
		return nil, nil, err
	}

	tag = otp.mac.Sum(nil)

	otp.mac.Reset()

	return ciphertext, tag, nil
}

// Open decrypts the ciphertext and verifies the HMAC
// Errors if decryption or verification fails.
// It uses HmacKey to validate the received value 'authData', and errors if
// verification fails.
func (otp *AuthenticatedOneTimePad) Open(ciphertext, authData, tag []byte) ([]byte, error) {
	// decrypt
	plaintext, err := common.XORBytes(otp.pad, ciphertext)
	if err != nil {
		return nil, err
	}

	_, err = otp.mac.Write(otp.nonce)
	if err != nil {
		return nil, err
	}

	_, err = otp.mac.Write(ciphertext)
	if err != nil {
		otp.mac.Reset()
		return nil, err
	}

	_, err = otp.mac.Write(authData)
	if err != nil {
		otp.mac.Reset()
		return nil, err
	}

	expTag := otp.mac.Sum(nil)
	otp.mac.Reset()

	if !hmac.Equal(expTag, tag) {
		return nil, common.ErrorHmacTagInvalid
	}

	return plaintext, nil
}
