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
	"reflect"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

func getDummyCredentials() (*Credentials, error) {
	userSigner, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	serverSigner, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	creds, err := newTestCredentials(userSigner, serverSigner.Public(), "server.com")
	if err != nil {
		return nil, err
	}
	return creds, nil
}

func TestMarshalUnmarshalCredentials(t *testing.T) {
	cred1, err := getDummyCredentials()
	if err != nil {
		t.Errorf("FAIL: get dummy creds failed: %v", err)
		return
	}

	cred2 := &Credentials{}
	if err := TestMarshalUnmarshal(cred1, cred2); err != nil {
		t.Error(err)
		return
	}
}

func TestMarshalUnmarshalCredentialExtension(t *testing.T) {
	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	credExt1, err := newCredentialExtension(CredentialTypeUserPublicKey, signer.Public())
	if err != nil {
		t.Error(err)
		return
	}

	credExt2 := &CredentialExtension{}
	if err := TestMarshalUnmarshal(credExt1, credExt2); err != nil {
		t.Error(err)
		return
	}
}

func TestEncryptDecryptCredentials(t *testing.T) {
	key := common.GetRandomBytes(32)
	nonceLen := 32

	creds1, err := getDummyCredentials() // user record does not matter for this test
	if err != nil {
		t.Errorf("FAIL: get dummy creds failed: %v", err)
		return
	}

	envelope, exportedKey, err := EncryptCredentials(key, creds1, nonceLen)
	if err != nil {
		t.Errorf("encryption error: %v", err)
		return
	}

	if len(exportedKey) == 0 {
		t.Errorf("exportedKey not set")
		return
	}

	creds2, err := DecryptCredentials(key, envelope)
	if err != nil {
		t.Errorf("decryption error: %v", err)
		return
	}

	if !reflect.DeepEqual(creds1, creds2) {
		t.Errorf("original/decrypted creds are different %v, %v ", creds1, creds2)
		return
	}
}

func TestCredentialEncryptionPolicy(t *testing.T) {
	c, err := NewClient("user", "server", oprf.OPRFP256)
	if err != nil {
		t.Error(err)
		return
	}

	clientSigner, err := mint.NewSigningKey(mint.ECDSA_P256_SHA256)
	if err != nil {
		t.Error(err)
		return
	}

	c.signer = clientSigner

	serverSigner, err := mint.NewSigningKey(mint.ECDSA_P256_SHA256)
	if err != nil {
		t.Error(err)
		return
	}

	policy1 := &CredentialEncodingPolicy{
		SecretTypes:    []CredentialType{CredentialTypeUserPrivateKey},
		CleartextTypes: []CredentialType{CredentialTypeServerIdentity, CredentialTypeServerPublicKey},
	}

	err = checkPolicy(c, serverSigner.Public(), policy1)
	if err != nil {
		t.Error(errors.Wrap(err, "default policy"))
		return
	}

	policy2 := &CredentialEncodingPolicy{
		SecretTypes: []CredentialType{CredentialTypeUserPrivateKey, CredentialTypeServerIdentity, CredentialTypeServerPublicKey},
	}

	err = checkPolicy(c, serverSigner.Public(), policy2)
	if err != nil {
		t.Error(errors.Wrap(err, "all secret policy"))
		return
	}

	badPolicy := &CredentialEncodingPolicy{
		CleartextTypes: []CredentialType{CredentialTypeUserPrivateKey, CredentialTypeServerIdentity, CredentialTypeServerPublicKey},
	}

	err = checkPolicy(c, serverSigner.Public(), badPolicy)
	if !errors.Is(err, common.ErrorForbiddenPolicy) {
		t.Error(errors.Wrap(err, "bad policy"))
		return
	}
}

func checkPolicy(client *Client, serverPublicKey crypto.PublicKey, policy *CredentialEncodingPolicy) error {
	creds, err := client.credentialsFromPolicy(policy, serverPublicKey)
	if err != nil {
		return errors.Wrap(err, "get creds")
	}

	err = checkCreds(creds.SecretCredentials, policy.SecretTypes)
	if err != nil {
		return errors.Wrap(err, "check secret creds")
	}

	err = checkCreds(creds.CleartextCredentials, policy.CleartextTypes)
	if err != nil {
		return errors.Wrap(err, "check cleartext creds")
	}

	key := common.GetRandomBytes(32)
	nonceLen := 32

	encrypted, _, err := EncryptCredentials(key, creds, nonceLen)
	if err != nil {
		return errors.Wrap(err, "encrypt creds")
	}

	if len(encrypted.EncryptedCreds) == 0 {
		return errors.New("encrypted creds should never be empty")
	}

	if len(encrypted.AuthenticatedCreds) == 0 && len(policy.CleartextTypes) != 0 {
		return errors.New("policy says authenticated creds should not be empty")
	}

	if len(encrypted.AuthTag) == 0 {
		return errors.New("auth tag must not be empty")
	}

	decrypted, err := DecryptCredentials(key, encrypted)
	if err != nil {
		return errors.Wrap(err, "decrypt creds")
	}

	if !reflect.DeepEqual(creds, decrypted) {
		return errors.Errorf("original/decrypted creds are different %v, %v ", creds, decrypted)
	}

	return nil
}

func checkCreds(credList CredentialExtensionList, credTypes []CredentialType) error {
	if len(credList) != len(credTypes) {
		return errors.New("credentials not encoded according to policy: lengths are different")
	}

	for _, credType := range credTypes {
		if _, ok := credList.Find(credType); !ok {
			return errors.Errorf("credentials not encoded according to policy: %v not found", credType)
		}
	}

	return nil
}

func TestFindCredentialExtensions(t *testing.T) {
	domain := "server.com"

	userSigner, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	serverSigner, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		t.Error(err)
		return
	}

	creds, err := newTestCredentials(userSigner, serverSigner.Public(), domain)
	if err != nil {
		t.Error(err)
		return
	}

	userSigner2, ok := creds.Find(CredentialTypeUserPrivateKey)
	if !ok {
		t.Errorf("user private key not in list")
	}

	if !reflect.DeepEqual(userSigner, userSigner2) {
		t.Errorf("user private keys do not match")
	}

	serverPublicKey2, ok := creds.Find(CredentialTypeServerPublicKey)
	if !ok {
		t.Errorf("server public key not in list")
	}

	if !reflect.DeepEqual(serverSigner.Public(), serverPublicKey2) {
		t.Errorf("server public keys do not match")
	}

	domain2, ok := creds.Find(CredentialTypeServerIdentity)
	if !ok {
		t.Errorf("server id not in list")
	}

	if !reflect.DeepEqual(domain, domain2) {
		t.Errorf("server ids do not match")
	}
}
