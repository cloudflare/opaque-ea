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
	"github.com/tatianab/mint/syntax"
)

// For labels.
const (
	ClientAuthMode      string = "client"
	ServerAuthMode      string = "server"
	HandshakeLabel      string = "handshake context"
	FinishedLabel       string = "finished key"
	ExpAuthContextLabel string = "Exported Authenticator"
)

// Party is a participant (client or server) in the EA flow
// Should be unique per TLS session, as it keeps track of contexts
// which may not be re-used.
type Party struct {
	isClient       bool
	sessions       map[string]*session
	getExportedKey ExportedKeyGetter
	authHash       crypto.Hash
}

// ExportedKeyGetter is a function that will be called by a party to
// get exported keys from labels.
// Can be set by caller or automatically set via a TLS connection.
type ExportedKeyGetter func(mode string, label string) ([]byte, error)

func newExportedKeyGetter(conn *mint.Conn) ExportedKeyGetter {
	return func(mode, label string) ([]byte, error) {
		return getExportedKeyFromTLSConn(conn, mode, label)
	}
}

// Server creates a new Party in the Server role.
// FUTURE: if TLS 1.2 and EMS was not negotiated, then return nil.
func Server(conn *mint.Conn) *Party {
	party := newPartyFromTLSConn(conn)
	party.isClient = false

	return party
}

// ServerFromGetter returns a new Party in the server role.
// It takes a function which outputs exporter keys based on labels, and
// a hash function that will be used in message authentication.
func ServerFromGetter(getExportedKey ExportedKeyGetter, authHash crypto.Hash) *Party {
	party := newPartyFromGetter(getExportedKey, authHash)
	party.isClient = false

	return party
}

// Client creates a new Party in the Client role.
func Client(conn *mint.Conn) *Party {
	party := newPartyFromTLSConn(conn)
	party.isClient = true

	return party
}

// ClientFromGetter returns a new Party in the client role.
// It takes a function which outputs exporter keys based on labels, and
// a hash function that will be used in message authentication.
func ClientFromGetter(getExportedKey ExportedKeyGetter, authHash crypto.Hash) *Party {
	party := newPartyFromGetter(getExportedKey, authHash)
	party.isClient = true

	return party
}

func newPartyFromTLSConn(conn *mint.Conn) *Party {
	return &Party{
		sessions:       make(map[string]*session),
		getExportedKey: newExportedKeyGetter(conn),
		authHash:       conn.ConnectionState().CipherSuite.Hash,
	}
}

func newPartyFromGetter(getExportedKey ExportedKeyGetter, authHash crypto.Hash) *Party {
	return &Party{
		sessions:       make(map[string]*session),
		getExportedKey: getExportedKey,
		authHash:       authHash,
	}
}

// newRequestorSession starts a new session for previously initialized Party
// in the Verifier role.
// Sets a fresh random, unique context for the session.
func (p *Party) newRequestorSession(req ExportedAuthenticatorRequest) (*session, error) {
	context, err := p.GetRandomUnusedContext()
	if err != nil {
		return nil, err
	}

	req.setContext(context)

	mode := ClientAuthMode
	if p.isClient {
		mode = ServerAuthMode
	}

	session := &session{
		context:    context,
		isVerifier: true,
		mode:       mode,
		req:        req,
		status:     sessionStatusRequest,
	}

	p.addSession(session)

	return session, nil
}

// newAuthenticatorSession starts a new session for a previously initialized Party
// in the Authenticator role, which sent an authenticator request.
// Must only be called after receiving an Authenticator Request message.
// It errors if the context (extracted from the Authenticator Request) is not unique.
// Returns the created session.
func (p *Party) newAuthenticatorSession(request ExportedAuthenticatorRequest) (*session, error) {
	if ok := p.validateContext(request.GetContext()); !ok {
		return nil, common.ErrorInvalidContext
	}

	mode := ServerAuthMode
	if p.isClient {
		mode = ClientAuthMode
	}

	session := &session{
		context:    request.GetContext(),
		isVerifier: false,
		mode:       mode,
		req:        request,
		status:     sessionStatusAuth,
	}

	p.addSession(session)

	return session, nil
}

// newSpontaneousAuthenticatorSession starts a new session for previously
// initialized Party in the Authenticator role.
// Must only be called by a Party in the Server role.
// Returns the created session, which has a random, unique context.
func (p *Party) newSpontaneousAuthenticatorSession() (*session, error) {
	if p.isClient {
		return nil, common.ErrorSpontaneousAuthForbidden
	}

	context, err := p.GetRandomUnusedContext()
	if err != nil {
		return nil, err
	}

	session := &session{
		context:    context,
		isVerifier: false,
		mode:       ServerAuthMode,
		req:        nil,
		status:     sessionStatusAuth,
	}

	p.addSession(session)

	return session, nil
}

// newVerifyOnlySession starts a new session for previously initialized Party
// in the Verifier role.
// Must be called by a Party in the Client role.
// Must only be called after receiving a Spontaneous Authenticator.
// Errors if the context is not unique.
// Returns the created session.
func (p *Party) newVerifyOnlySession(ea *ExportedAuthenticator) (*session, error) {
	if !p.isClient {
		return nil, common.ErrorIncorrectRole
	}

	if ok := p.validateContext(ea.GetContext()); !ok {
		return nil, common.ErrorInvalidContext
	}

	session := &session{
		context:    ea.GetContext(),
		isVerifier: true,
		mode:       ServerAuthMode,
		req:        nil,
		ea:         ea,
		status:     sessionStatusVerify,
	}

	p.addSession(session)

	return session, nil
}

// look up and return existing requestor session. error if session is in wrong
// role or wrong state.
func (p *Party) getRequestorSessionForVerify(context []byte, ea *ExportedAuthenticator) (s *session, err error) {
	var ok bool

	if s, ok = p.getSession(context); !ok {
		return nil, common.ErrorSessionNotFound
	}

	if s.status != sessionStatusRequest {
		return nil, common.ErrorIncorrectState
	}

	if !s.isVerifier {
		return nil, common.ErrorIncorrectRole
	}

	s.status = sessionStatusVerify
	s.ea = ea

	return s, nil
}

// look up and return the session associated with the given context, return false
// if none exists.
func (p *Party) getSession(context []byte) (*session, bool) {
	s, ok := p.sessions[string(context)]
	return s, ok
}

// adds a new session. caller is responsible for validating that context
// has not been re-used.
func (p *Party) addSession(s *session) {
	p.sessions[string(s.context)] = s
}

type session struct {
	status     sessionStatus
	isVerifier bool

	ea  *ExportedAuthenticator
	req ExportedAuthenticatorRequest

	context []byte
	mode    string
}

type sessionStatus uint16

const (
	sessionStatusRequest sessionStatus = 1 + iota // request stage
	sessionStatusAuth                             // authentication stage
	sessionStatusVerify                           // verification stage
	sessionStatusComplete
)

func (s *session) Complete() {
	s.status = sessionStatusComplete
}

// ExportedAuthenticator is an exported authenticator.
// Non-empty EAs must contain Certificate, Certificate Verify and Finished
// messages.
// Empty EAs contain only a Finished message.
type ExportedAuthenticator struct {
	publicKey  crypto.PublicKey            // only for OPAQUE - kind of a hack
	CertMsg    *mint.CertificateBody       // optional
	CertVerify *mint.CertificateVerifyBody // optional
	Finished   *mint.FinishedBody          // mandatory
}

// IsEmpty returns whether the given EA is empty.
func (ea *ExportedAuthenticator) IsEmpty() bool {
	return ea.CertMsg == nil || ea.CertVerify == nil
}

// Extensions returns the list of extensions in the given EA.
func (ea *ExportedAuthenticator) Extensions() mint.ExtensionList {
	if ea.CertMsg == nil || len(ea.CertMsg.CertificateList) == 0 {
		return mint.ExtensionList{}
	}

	return ea.CertMsg.CertificateList[0].Extensions
}

type exportedAuthenticatorInner struct {
	CertMsg    *TLSMessage `tls:"optional"`
	CertVerify *TLSMessage `tls:"optional"`
	Finished   *TLSMessage
}

// Marshal returns the raw data included in this EA.
// May be called on empty and non-empty EAs.
// The Certificate, CertificateVerify (if present) and Finished messages have
// standard TLS headers: one type byte and three length bytes.
func (ea *ExportedAuthenticator) Marshal() ([]byte, error) {
	var certMsg, certVerify, finished *TLSMessage
	var err error

	if ea.CertMsg != nil {
		certMsg, err = TLSMessageFromBody(ea.CertMsg)
		if err != nil {
			return nil, err
		}
	}

	if ea.CertVerify != nil {
		certVerify, err = TLSMessageFromBody(ea.CertVerify)
		if err != nil {
			return nil, err
		}
	}

	finished, err = TLSMessageFromBody(ea.Finished)
	if err != nil {
		return nil, err
	}

	inner := exportedAuthenticatorInner{
		CertMsg:    certMsg,
		CertVerify: certVerify,
		Finished:   finished,
	}

	return syntax.Marshal(inner)
}

// Unmarshal parses the given raw data into an EA struct and returns the number
// of bytes read. The given raw data may be longer than the raw EA.
// The raw data must be formatted as returned by Marshal.
func (ea *ExportedAuthenticator) Unmarshal(data []byte) (int, error) {
	inner := &exportedAuthenticatorInner{}

	bytesRead, err := syntax.Unmarshal(data, inner)
	if err != nil {
		return 0, err
	}

	var body, finished mint.HandshakeMessageBody
	var certMsg *mint.CertificateBody
	var certVerify *mint.CertificateVerifyBody
	var pubKey crypto.PublicKey

	if inner.CertMsg != nil {
		body, err = inner.CertMsg.ToBody()
		if err != nil {
			return 0, err
		}

		certMsg = body.(*mint.CertificateBody)

		pubKey, err = getLeafPublicKey(certMsg)
		if err != nil {
			pubKey = nil
		}
	}

	if inner.CertVerify != nil {
		body, err = inner.CertVerify.ToBody()
		if err != nil {
			return 0, err
		}

		certVerify = body.(*mint.CertificateVerifyBody)
	}

	finished, err = inner.Finished.ToBody()
	if err != nil {
		return 0, err
	}

	*ea = ExportedAuthenticator{
		CertMsg:    certMsg,
		CertVerify: certVerify,
		Finished:   finished.(*mint.FinishedBody),
	}

	ea.publicKey = pubKey

	return bytesRead, nil
}

// SetPublicKey sets the public key to be used in verification of this EA.
// It should be called by the Verifier if the public key to be used is not
// present in the Certificate message.
// (For example, in the OPAQUE-EA protocol, the public key used for verification
// is secret and must not be revealed by the EA).
func (ea *ExportedAuthenticator) SetPublicKey(pubKey crypto.PublicKey) {
	ea.publicKey = pubKey
}

// LeafPublicKey returns the Public Key associated with this EA.
// If the EA has not been modified via SetPublicKey, it returns the public key
// associated with the leaf of the certificate chain in the Certificate message.
func (ea *ExportedAuthenticator) LeafPublicKey() crypto.PublicKey {
	return ea.publicKey
}

// GetContext returns the context associated with this EA.
// Must only be called on non-empty EAs.
// For empty EAs, the context should be extracted from the original
// Authenticator Request via its GetContext method.
func (ea *ExportedAuthenticator) GetContext() []byte {
	return ea.CertMsg.CertificateRequestContext
}

// CertChain returns the list of Certificate Entries that is inside this EA's
// Certificate message. If the EA is empty, an empty list is returned.
func (ea *ExportedAuthenticator) CertChain() []mint.CertificateEntry {
	if ea.IsEmpty() {
		return []mint.CertificateEntry{}
	}

	return ea.CertMsg.CertificateList
}

// ExportedAuthenticatorRequest is a request for an exported authenticator.
type ExportedAuthenticatorRequest interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) (int, error)
	GetContext() []byte
	SupportedSignatureSchemes() ([]mint.SignatureScheme, error)
	GetExtensions() mint.ExtensionList

	setContext([]byte)
}

// ServerExportedAuthenticatorRequest is an EA request made by a Server.
type ServerExportedAuthenticatorRequest mint.CertificateRequestBody

// ClientExportedAuthenticatorRequest is an EA request made by a Client.
type ClientExportedAuthenticatorRequest mint.CertificateRequestBody

// Marshal returns the raw data for this Server EA request.
func (req *ServerExportedAuthenticatorRequest) Marshal() ([]byte, error) {
	return (*mint.CertificateRequestBody)(req).Marshal()
}

// Unmarshal converts the given raw data into a Server EA request and returns
// the number of bytes read.
func (req *ServerExportedAuthenticatorRequest) Unmarshal(data []byte) (int, error) {
	return (*mint.CertificateRequestBody)(req).Unmarshal(data)
}

// GetContext returns the CertificateRequestContext for this Server EA request.
func (req *ServerExportedAuthenticatorRequest) GetContext() []byte {
	return req.CertificateRequestContext
}

// GetExtensions returns the extensions included in this Server EA request.
func (req *ServerExportedAuthenticatorRequest) GetExtensions() mint.ExtensionList {
	return req.Extensions
}

// SupportedSignatureSchemes returns a list of the signature algorithms advertised as
// supported by this Server EA request.
func (req *ServerExportedAuthenticatorRequest) SupportedSignatureSchemes() ([]mint.SignatureScheme, error) {
	schemes := mint.SignatureAlgorithmsExtension{}

	_, err := req.Extensions.Find(&schemes)
	if err != nil {
		return nil, err
	}

	return schemes.Algorithms, nil
}

func (req *ServerExportedAuthenticatorRequest) setContext(context []byte) {
	req.CertificateRequestContext = context
}

// Marshal returns the raw data for this Client EA request.
func (req *ClientExportedAuthenticatorRequest) Marshal() ([]byte, error) {
	return (*mint.CertificateRequestBody)(req).Marshal()
}

// Unmarshal converts the given raw data into a Client EA request and returns
// the number of bytes read.
func (req *ClientExportedAuthenticatorRequest) Unmarshal(data []byte) (int, error) {
	return (*mint.CertificateRequestBody)(req).Unmarshal(data)
}

// GetContext returns the CertificateRequestContext for this Client EA request.
func (req *ClientExportedAuthenticatorRequest) GetContext() []byte {
	return req.CertificateRequestContext
}

// GetExtensions returns the extensions included in this Client EA request.
func (req *ClientExportedAuthenticatorRequest) GetExtensions() mint.ExtensionList {
	return req.Extensions
}

// SupportedSignatureSchemes returns a list of the signature algorithms advertised as
// supported by this Client EA request.
func (req *ClientExportedAuthenticatorRequest) SupportedSignatureSchemes() ([]mint.SignatureScheme, error) {
	schemes := mint.SignatureAlgorithmsExtension{}

	_, err := req.Extensions.Find(&schemes)
	if err != nil {
		return nil, err
	}

	return schemes.Algorithms, nil
}

func (req *ClientExportedAuthenticatorRequest) setContext(context []byte) {
	req.CertificateRequestContext = context
}
