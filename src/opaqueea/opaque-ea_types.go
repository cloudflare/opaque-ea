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

package opaqueea

import (
	"crypto"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
)

// Client is an instance of an OPAQUE-EA client.
type Client struct {
	eaState           *expauth.Party
	opaqueState       *opaque.Client
	request           expauth.ExportedAuthenticatorRequest
	validatePublicKey func(crypto.PublicKey) bool
}

// Server is an instance of an OPAQUE-EA server.
type Server struct {
	cfg       *ServerConfig
	connState *ConnectionState
}

// ServerConfig represents a configuration for a server, with an OPAQUE configuration
// and a handle.
type ServerConfig struct {
	OpaqueCfg         *opaque.ServerConfig
	HandleMissingUser func(error) (*ServerResponseMsg, error)
}

// ConnectionState represents the state of a connection.
type ConnectionState struct {
	opaqueServer *opaque.Server
	eaState      *expauth.Party
	request      expauth.ExportedAuthenticatorRequest
}

// NewServer takes in a server exported authenticator state and a signing key
// and returns a new OPAQUE-EA server instance.
func NewServer(state *expauth.Party, cfg *ServerConfig) (*Server, error) {
	opaqueState, err := opaque.NewServer(cfg.OpaqueCfg)
	if err != nil {
		return nil, err
	}

	if cfg.HandleMissingUser == nil {
		cfg.HandleMissingUser = errorOnMissingUser
	}

	return &Server{
		cfg: cfg,
		connState: &ConnectionState{
			opaqueServer: opaqueState,
			eaState:      state,
		},
	}, nil
}

// GetUserID gets the user id.
func (s *Server) GetUserID() string {
	return string(s.connState.opaqueServer.UserRecord.UserID)
}

// NewClient takes an existing client exported authenticator state
// and a user ID and returns a new OPAQUE-EA client instance.
func NewClient(state *expauth.Party, userID, domain string, suite oprf.SuiteID) (*Client, error) {
	opaqueState, err := opaque.NewClient(userID, domain, suite)
	if err != nil {
		return nil, err
	}

	return &Client{
		eaState:           state,
		opaqueState:       opaqueState,
		validatePublicKey: func(crypto.PublicKey) bool { return true }, // TODO: make this a param
	}, nil
}

func errorOnMissingUser(err error) (*ServerResponseMsg, error) {
	return nil, err
}
