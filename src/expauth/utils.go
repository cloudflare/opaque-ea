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

package expauth

import (
	"crypto"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/tatianab/mint"
)

const (
	//ExpAuthTestSignatureScheme represents the signature scheme for exported authenticators.
	ExpAuthTestSignatureScheme mint.SignatureScheme = mint.ECDSA_P521_SHA512
)

const keyLen = 32

var key1 []byte = common.GetRandomBytes(keyLen)
var key2 []byte = common.GetRandomBytes(keyLen)
var key3 []byte = common.GetRandomBytes(keyLen)
var key4 []byte = common.GetRandomBytes(keyLen)

// GetTestGetterAndHash gets the getter and hasher.
func GetTestGetterAndHash() (ExportedKeyGetter, crypto.Hash) {
	return ExportedKeyGetterFromKeys(key1, key2, key3, key4), common.HashMap[ExpAuthTestSignatureScheme]
}

func getTestClientServer() (client, server *Party) {
	ekg, h := GetTestGetterAndHash()
	return ClientFromGetter(ekg, h), ServerFromGetter(ekg, h)
}
