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
	"bytes"
	"testing"

	"github.com/cloudflare/opaque-ea/src/common"
)

func TestOTPEncryptDecrypt(t *testing.T) {
	key := common.GetRandomBytes(32)
	nonce := common.GetRandomBytes(32)

	plaintext := []byte("plaintext")
	authData := []byte("authdata")

	otp, err := NewAuthenticatedOneTimePad(key, nonce, len(plaintext))
	if err != nil {
		t.Errorf("otp init: %v", err)
	}

	ciphertext, tag, err := otp.Seal(plaintext, authData)
	if err != nil {
		t.Errorf("encryption error: %v", err)
	}

	otp, err = NewAuthenticatedOneTimePad(key, nonce, len(ciphertext))
	if err != nil {
		t.Errorf("otp init: %v", err)
	}

	plaintext2, err := otp.Open(ciphertext, authData, tag)
	if err != nil {
		t.Errorf("decryption error: %v", err)
	}

	if !bytes.Equal(plaintext, plaintext2) {
		t.Errorf("incorrect decrypted plaintext")
	}
}
