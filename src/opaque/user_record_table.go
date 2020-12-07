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
	"strings"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

// UserRecord holds the data stored by the server about the user.
// The values UserPublicKey and OprfState should be kept secret.
type UserRecord struct {
	UserID        []byte
	UserPublicKey crypto.PublicKey
	OprfState     *oprf.Server
	Envelope      *Envelope
}

// UserRecordTable is an interface for password storage and lookup.
type UserRecordTable interface {
	InsertUserRecord(string, *UserRecord) error
	LookupUserRecord(string) (*UserRecord, error)
}

// InMemoryUserRecordTable is a map from usernames to user records to mimic a
// database. Implements UserRecordTable.
type InMemoryUserRecordTable map[string]*UserRecord

// NewServerConfig returns a ServerConfig struct containing
// a fresh signing key and an empty lookup table
func NewServerConfig(domain string, suite oprf.SuiteID) (cfg *ServerConfig, err error) {
	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	t := NewInMemoryUserRecordTable()

	return &ServerConfig{
		ServerID:    domain,
		Signer:      signer,
		RecordTable: t,
		Suite:       suite,
	}, nil
}

// NewInMemoryUserRecordTable returns a new empty in-memory user record table.
func NewInMemoryUserRecordTable() *InMemoryUserRecordTable {
	t := make(map[string]*UserRecord)
	return (*InMemoryUserRecordTable)(&t)
}

// LookupUserRecord returns the user record associated with the given username in the
// user record, or an error if the username is not registered.
func (t InMemoryUserRecordTable) LookupUserRecord(username string) (*UserRecord, error) {
	record, ok := map[string]*UserRecord(t)[username]
	if !ok {
		return nil, errors.Wrapf(common.ErrorUserNotRegistered, username)
	}

	return record, nil
}

// InsertUserRecord adds a record to the in-memory user record table.
// Username must be unique. The UserID in the record must be nil or match the
// given username.
func (t InMemoryUserRecordTable) InsertUserRecord(username string, record *UserRecord) error {
	// validate username
	if len(record.UserID) == 0 {
		record.UserID = []byte(username)
	} else if strings.Compare(string(record.UserID), username) != 0 {
		return errors.Wrapf(common.ErrorUnexpectedData, string(record.UserID), username)
	}

	if _, in := map[string]*UserRecord(t)[username]; in {
		return errors.Wrapf(common.ErrorUserAlreadyRegistered, string(record.UserID))
	}

	// insert user
	map[string]*UserRecord(t)[username] = record

	return nil
}

// BulkAdd adds the given records to the in-memory user record table.
func (t InMemoryUserRecordTable) BulkAdd(records []*UserRecord) error {
	for _, record := range records {
		err := t.InsertUserRecord(string(record.UserID), record)
		if err != nil {
			return err
		}
	}

	return nil
}

// newTestCredentials returns Credentials for testing packaged as
// secret: userPrivateKey | cleartext: serverPublicKey, domain
func newTestCredentials(userPrivateKey crypto.Signer, serverPublicKey crypto.PublicKey, domain string) (*Credentials, error) {
	upk, err := newCredentialExtension(CredentialTypeUserPrivateKey, userPrivateKey)
	if err != nil {
		return nil, err
	}

	spk, err := newCredentialExtension(CredentialTypeServerPublicKey, serverPublicKey)
	if err != nil {
		return nil, err
	}

	sid, err := newCredentialExtension(CredentialTypeServerIdentity, []byte(domain))
	if err != nil {
		return nil, err
	}

	// use default policy
	return &Credentials{
		SecretCredentials:    []*CredentialExtension{upk},
		CleartextCredentials: []*CredentialExtension{spk, sid},
	}, nil
}
