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

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
)

// Server holds state for an instance of the server role in OPAQUE.
type Server struct {
	Config     *ServerConfig
	UserRecord *UserRecord
}

// ServerConfig holds long term state for the server.
type ServerConfig struct {
	ServerID                 string
	Signer                   crypto.Signer
	RecordTable              UserRecordTable
	Suite                    oprf.SuiteID
	CredentialEncodingPolicy *CredentialEncodingPolicy
}

// CredentialEncodingPolicy indicates which user credentials are stored,
// and whether they are held encrypted or in cleartext.
type CredentialEncodingPolicy struct {
	SecretTypes    []CredentialType
	CleartextTypes []CredentialType
}

// Client holds state for the client role in OPAQUE.
type Client struct {
	UserID    []byte
	ServerID  []byte
	oprf1     *oprf.ClientRequest
	oprfState *oprf.Client
	signer    crypto.Signer // this value will be assigned during registration
	suite     oprf.SuiteID
}

// NewServer returns a new OPAQUE server with the RECOMMENDED credential
// encoding policy.
func NewServer(cfg *ServerConfig) (*Server, error) {
	if cfg.CredentialEncodingPolicy == nil {
		cfg.CredentialEncodingPolicy = &CredentialEncodingPolicy{
			SecretTypes: []CredentialType{
				CredentialTypeUserPrivateKey,
			},
			CleartextTypes: []CredentialType{
				CredentialTypeServerPublicKey,
				CredentialTypeServerIdentity,
			},
		}
	}

	return &Server{Config: cfg, UserRecord: &UserRecord{}}, nil
}

// SetUserID sets the User ID for the Server's User Record.
func (s *Server) SetUserID(userID []byte) error {
	record, err := s.Config.RecordTable.LookupUserRecord(string(userID))
	if record != nil && err == nil {
		return common.ErrorUserAlreadyRegistered
	}

	s.UserRecord.UserID = userID

	return nil
}

// GetUserRecordFromUsername looks up the user record associated with the
// given username, and uses it to set the server's user record.
// Errors if no user record can be found, or there is no LookupUserRecord set.
func (s *Server) GetUserRecordFromUsername(username []byte) (*UserRecord, error) {
	if s.Config.RecordTable == nil {
		return nil, common.ErrorNoPasswordTable
	}

	userRecord, err := s.Config.RecordTable.LookupUserRecord(string(username))
	if err != nil {
		return nil, err
	}
	s.UserRecord = userRecord

	return userRecord, nil
}

// InsertNewUserRecord updates the server's user record struct with the given data,
// registers the record using the InsertUserRecord, and returns the created record.
func (s *Server) InsertNewUserRecord(userPublicKey crypto.PublicKey, envelope *Envelope) (*UserRecord, error) {
	record := s.UserRecord
	record.Envelope = envelope
	record.UserPublicKey = userPublicKey

	if s.Config.RecordTable != nil {
		if err := s.Config.RecordTable.InsertUserRecord(string(record.UserID), record); err != nil {
			return nil, err
		}
	}

	return record, nil
}

// NewClient returns a new OPAQUE client.
func NewClient(userID, serverID string, suite oprf.SuiteID) (*Client, error) {
	oprfClient, err := oprf.NewClient(suite)
	if err != nil {
		return nil, err
	}

	return &Client{
		UserID:    []byte(userID),
		ServerID:  []byte(serverID),
		oprfState: oprfClient,
		suite:     suite,
	}, nil
}
