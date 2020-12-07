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
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"hash"

	"github.com/pkg/errors"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/tatianab/mint"
)

// Request returns a new ExportedAuthenticatorRequest of the appropriate type
// (Client if the calling peer is a Client, else Server).
// It chooses a fresh context and creates a new requestor session for the Party.
func (p *Party) Request(extensions mint.ExtensionList) (ExportedAuthenticatorRequest, error) {
	var req ExportedAuthenticatorRequest

	if p.isClient {
		req = &ClientExportedAuthenticatorRequest{
			Extensions: extensions,
		}
	} else {
		req = &ServerExportedAuthenticatorRequest{
			Extensions: extensions,
		}
	}

	// creates and adds a context
	_, err := p.newRequestorSession(req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// Authenticate returns a new ExportedAuthenticator for the defined Party.
func (p *Party) Authenticate(certs []*mint.Certificate, exts mint.ExtensionList,
	request ExportedAuthenticatorRequest) (*ExportedAuthenticator, error) {
	/*
		The "authenticate" API takes as input:

		o  a reference to an active connection
		o  a set of certificate chains and associated extensions (OCSP, SCT,
		   etc.)
		o  a signer (either the private key associated with the certificate,
		   or interface to perform private key operations) for each chain
		o  an authenticator request or certificate_request_context (from 0 to
		   255 bytes)

		It returns either the exported authenticator or an empty
		authenticator as a sequence of octets.  It is RECOMMENDED that the
		logic for selecting the certificates and extensions to include in the
		exporter is implemented in the TLS library.  Implementing this in the
		TLS library lets the implementer take advantage of existing extension
		and certificate selection logic and more easily remember which
		extensions were sent in the ClientHello.
	*/
	session, err := p.newAuthenticatorSession(request)
	if err != nil {
		return nil, err
	}

	return p.getExportedAuthenticator(certs, exts, session)
}

// AuthenticateSpontaneously returns a new ExportedAuthenticator.
// Must only be called by a Server.
// It creates a new spontaneous authenticator session for the Party.
func (p *Party) AuthenticateSpontaneously(certs []*mint.Certificate, exts mint.ExtensionList) (*ExportedAuthenticator, error) {
	session, err := p.newSpontaneousAuthenticatorSession()
	if err != nil {
		return nil, err
	}

	return p.getExportedAuthenticator(certs, exts, session)
}

// TODO: consider refactoring.
func (p *Party) getExportedAuthenticator(certs []*mint.Certificate, exts mint.ExtensionList,
	s *session) (*ExportedAuthenticator, error) {
	defer s.Complete()

	// Input Validation
	if len(certs) == 0 {
		return nil, common.ErrorNoCertificates
	}

	schemes, err := extractSupportedSignatureSchemes(s.req)
	if err != nil {
		return nil, err
	}

	cert, sigAlg, err := mint.CertificateSelection(nil, schemes.Algorithms, certs)
	if err != nil {
		return nil, err
	}

	// Add chosen alg to extensions list
	err = exts.Add(&mint.SignatureAlgorithmsExtension{
		Algorithms: []mint.SignatureScheme{sigAlg},
	})
	if err != nil {
		return nil, err
	}

	certMsg, certVerify, finished, err := p.getHandshakeMessages(cert, exts, sigAlg, s)
	if err != nil {
		return nil, err
	}

	pubKey, err := getLeafPublicKey(certMsg)
	if err != nil {
		return nil, err
	}

	ea := &ExportedAuthenticator{
		publicKey:  pubKey,
		CertMsg:    certMsg,
		CertVerify: certVerify,
		Finished:   finished,
	}

	return ea, nil
}

func (p *Party) getHandshakeMessages(cert *mint.Certificate, exts mint.ExtensionList,
	sigAlg mint.SignatureScheme, s *session) (*mint.CertificateBody, *mint.CertificateVerifyBody, *mint.FinishedBody, error) {
	handshakeContext, err := p.getExportedKey(s.mode, HandshakeLabel)
	if err != nil {
		return nil, nil, nil, err
	}

	certMsg, err := getCertMsg(cert, s.context, exts)
	if err != nil {
		return nil, nil, nil, err
	}

	// Hash(Handshake Context || authenticator request || Certificate)
	transcript := initTranscript(p.authHash.New())
	transcript.setHandshakeContext(handshakeContext)
	transcript.setRequest(s.req)
	transcript.setCert(certMsg)

	err = transcript.hash()
	if err != nil {
		return nil, nil, nil, err
	}

	// TODO: in TLS 1.3 certVerify does not accept RSASSA-PKCS1-v1_5 algos.
	// It seems that is not validated.
	certVerify, err := getCertVerify(cert.PrivateKey, sigAlg, transcript.hashed)
	if err != nil {
		return nil, nil, nil, err
	}

	// Hash(Handshake Context || authenticator request || Certificate || CertificateVerify)
	transcript.setCertVerify(certVerify)
	err = transcript.hash()
	if err != nil {
		return nil, nil, nil, err
	}

	// Finished = HMAC(Finished MAC Key, Hash(Handshake Context || authenticator request || Certificate || CertificateVerify))
	finished, err := p.getFinishedMsg(transcript.hashed, s.mode)
	if err != nil {
		return nil, nil, nil, err
	}

	return certMsg, certVerify, finished, nil
}

func extractSupportedSignatureSchemes(req ExportedAuthenticatorRequest) (*mint.SignatureAlgorithmsExtension, error) {
	schemes := mint.SignatureAlgorithmsExtension{}

	if req != nil {
		ok, err := req.GetExtensions().Find(&schemes)
		if !ok {
			return nil, errors.Wrapf(common.ErrorNotFound, "signature algorithms extension")
		}

		if err != nil {
			return nil, err
		}
	} else {
		// FUTURE: get schemes (from client hello) if no req provided (probably need to go inside mint)
		// For now, accepted schemes are hard-coded
		schemes = mint.SignatureAlgorithmsExtension{Algorithms: common.MintSupportedSignatureSchemes}
	}

	return &schemes, nil
}

type transcriptStatus uint8

const (
	transcriptStatusEmpty    transcriptStatus = 0
	transcriptStatusNoCV     transcriptStatus = 1
	transcriptStatusComplete transcriptStatus = 2
)

type transcript struct {
	hashed hash.Hash
	hc     []byte
	req    ExportedAuthenticatorRequest
	cm     *mint.CertificateBody
	cv     *mint.CertificateVerifyBody
	status transcriptStatus
}

func initTranscript(ht hash.Hash) *transcript {
	return &transcript{hashed: ht, status: transcriptStatusEmpty}
}

func (t *transcript) setHandshakeContext(hc []byte) {
	t.hc = hc
}

func (t *transcript) setRequest(req ExportedAuthenticatorRequest) {
	t.req = req
}

func (t *transcript) setCert(cert *mint.CertificateBody) {
	t.cm = cert
}

func (t *transcript) setCertVerify(cv *mint.CertificateVerifyBody) {
	t.cv = cv
}

func (t *transcript) hash() error {
	// Hash( Handshake Context || authenticator request || CertificateMsg || CertificateVerify (if present/needed))
	var raw []byte
	var err error

	if t.status == transcriptStatusEmpty {
		_, err = t.hashed.Write(t.hc)
		if err != nil {
			return err
		}

		if t.req != nil {
			raw, err = t.req.Marshal()
			if err != nil {
				return err
			}

			_, err = t.hashed.Write(raw)
			if err != nil {
				return err
			}
		}

		raw, err = t.cm.Marshal()
		if err != nil {
			return err
		}

		_, err = t.hashed.Write(raw)
		if err != nil {
			return err
		}

		t.status = transcriptStatusNoCV
	}

	if t.status == transcriptStatusNoCV && t.cv != nil {
		raw, err = t.cv.Marshal()
		if err != nil {
			return err
		}

		_, err = t.hashed.Write(raw)
		if err != nil {
			return err
		}

		t.status = transcriptStatusComplete
	}

	return nil
}

// RefuseAuthentication takes an EA request and returns a new empty
// ExportedAuthenticator, indicating that the Party cannot or does not want
// to authenticate.
func (p *Party) RefuseAuthentication(request ExportedAuthenticatorRequest) (*ExportedAuthenticator, error) {
	/*
		If, given an authenticator request, the endpoint does not have an
		appropriate certificate or does not want to return one, it constructs
		an authenticated refusal called an empty authenticator.  This is a
		Finished message sent without a Certificate or CertificateVerify.
		This message is an HMAC over the hashed authenticator transcript with
		a Certificate message containing no CertificateEntries and the
		CertificateVerify message omitted.

		Finished = HMAC(Finished MAC Key, Hash(Handshake Context ||
			 authenticator request || Certificate))
	*/
	session, err := p.newAuthenticatorSession(request)
	if err != nil {
		return nil, err
	}

	session.Complete() // complete regardless of outcome

	if p.isClient {
		return p.getEmptyAuthenticator(session)
	}

	return p.getEmptyAuthenticator(session)
}

func (p *Party) getEmptyAuthenticator(s *session) (*ExportedAuthenticator, error) {
	defer s.Complete()

	handshakeContext, err := p.getExportedKey(s.mode, HandshakeLabel)
	if err != nil {
		return nil, err
	}

	// Hash(Handshake Context || authenticator request || Empty Certificate)
	transcript := initTranscript(p.authHash.New())
	transcript.setHandshakeContext(handshakeContext)
	transcript.setRequest(s.req)
	transcript.setCert(getEmptyCert(s.req.GetContext()))

	err = transcript.hash()
	if err != nil {
		return nil, err
	}

	finished, err := p.getFinishedMsg(transcript.hashed, s.mode)
	if err != nil {
		return nil, err
	}

	return &ExportedAuthenticator{
		Finished: finished,
	}, nil
}

func getCertMsg(cert *mint.Certificate, context []byte, exts mint.ExtensionList) (*mint.CertificateBody, error) {
	if cert == nil {
		return &mint.CertificateBody{
			CertificateRequestContext: context,
			CertificateList:           []mint.CertificateEntry{},
		}, nil
	}

	certMsg := &mint.CertificateBody{
		CertificateRequestContext: context,
		CertificateList:           certToCertEntries(cert, exts),
	}

	_, err := certMsg.Marshal()
	if err != nil {
		return nil, err
	}

	return certMsg, nil
}

// TODO: is it correct to add extensions to all certs? or should they just be added to the leaf?
func certToCertEntries(cert *mint.Certificate, exts mint.ExtensionList) []mint.CertificateEntry {
	entries := []mint.CertificateEntry{}
	for _, x509cert := range cert.Chain {
		entries = append(entries, mint.CertificateEntry{CertData: x509cert, Extensions: exts})
	}

	return entries
}

func getExportedKeyFromTLSConn(conn *mint.Conn, mode, label string) ([]byte, error) {
	keyLength := conn.ConnectionState().CipherSuite.Hash.Size()
	fullLabel := fmt.Sprintf("EXPORTER-%s authenticator %s", mode, label)

	key, err := conn.ComputeExporter(fullLabel, nil, keyLength)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func getCertVerify(signer crypto.Signer, sigAlg mint.SignatureScheme, ht hash.Hash) (*mint.CertificateVerifyBody, error) {
	certVerify := &mint.CertificateVerifyBody{
		Algorithm: sigAlg,
	}

	if err := certVerify.SignWithContext(signer, ht.Sum(nil), ExpAuthContextLabel); err != nil {
		return nil, err
	}

	_, err := certVerify.Marshal()
	if err != nil {
		return nil, err
	}

	return certVerify, nil
}

func (p *Party) getFinishedMsg(hashedTranscript hash.Hash, mode string) (*mint.FinishedBody, error) {
	key, err := p.getExportedKey(mode, FinishedLabel)
	if err != nil {
		return nil, err
	}

	verifyDataHash := hmac.New(p.authHash.New, key)
	_, err = verifyDataHash.Write(hashedTranscript.Sum(nil))
	if err != nil {
		return nil, err
	}

	verifyData := verifyDataHash.Sum(nil)
	finished := &mint.FinishedBody{
		VerifyData:    verifyData,
		VerifyDataLen: len(verifyData),
	}

	_, err = finished.Marshal()
	if err != nil {
		return nil, err
	}

	return finished, nil
}

// Validate takes in an EA and an EA request, and determines whether the EA
// is valid with respect to the request. A well-formed empty EA is invalid.
// It returns the certificate chain and extensions associated with the EA
// and errors if the EA is invalid.
// The calling function is responsible for verifying the certificate chain.
func (p *Party) Validate(ea *ExportedAuthenticator,
	request ExportedAuthenticatorRequest) ([]mint.CertificateEntry, mint.ExtensionList, error) {
	/*
	   The "validate" API takes as input:

	   o  a reference to an active connection
	   o  an optional authenticator request
	   o  an authenticator

	   It returns the certificate chain and extensions and a status to
	   indicate whether the authenticator is valid or not.  If the
	   authenticator was empty - that is, it did not contain a certificate -
	   the certificate chain will contain no certificates.  The API SHOULD
	   return a failure if the certificate_request_context of the
	   authenticator was used in a previously validated authenticator.
	   Well-formed empty authenticators are returned as invalid.
	*/
	var context []byte
	if ea.IsEmpty() {
		return nil, nil, errors.New("Invalid Exported Authenticator")
	}

	context = ea.GetContext()
	if request != nil && !bytes.Equal(context, request.GetContext()) {
		return nil, nil, common.ErrorInconsistentContext
	}

	var session *session
	var err error
	if request == nil {
		session, err = p.newVerifyOnlySession(ea)
		if err != nil {
			return nil, nil, err
		}
	} else {
		session, err = p.getRequestorSessionForVerify(context, ea)
		if err != nil {
			return nil, nil, err
		}
	}

	return p.validate(session, ea.publicKey)
}

func (p *Party) validate(s *session, publicKey crypto.PublicKey) ([]mint.CertificateEntry, mint.ExtensionList, error) {
	defer s.Complete()

	handshakeContext, err := p.getExportedKey(s.mode, HandshakeLabel)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get exported key")
	}

	// Hash(Handshake Context || authenticator request || Certificate)
	transcript := initTranscript(p.authHash.New())
	transcript.setHandshakeContext(handshakeContext)
	transcript.setRequest(s.req)
	transcript.setCert(s.ea.CertMsg)

	err = transcript.hash()
	if err != nil {
		return nil, nil, err
	}

	err = validateCertVerify(s.ea.CertVerify, publicKey, transcript.hashed)
	if err != nil {
		return nil, nil, err
	}

	// Hash(Handshake Context || authenticator request || Certificate || CertificateVerify)
	transcript.setCertVerify(s.ea.CertVerify)
	err = transcript.hash()
	if err != nil {
		return nil, nil, err
	}

	err = p.validateFinished(s.ea.Finished, transcript.hashed, s.mode)
	if err != nil {
		return nil, nil, err
	}

	return s.ea.CertChain(), s.ea.Extensions(), nil
}

func validateCertVerify(cv *mint.CertificateVerifyBody, publicKey crypto.PublicKey, ht hash.Hash) error {
	if err := cv.VerifyWithContext(publicKey, ht.Sum(nil), ExpAuthContextLabel); err != nil {
		return err
	}

	return nil
}

func getLeafPublicKey(certMsg *mint.CertificateBody) (crypto.PublicKey, error) {
	if len(certMsg.CertificateList) == 0 {
		return nil, common.ErrorNoCertificates
	}

	return certMsg.CertificateList[0].CertData.PublicKey, nil
}

func (p *Party) validateFinished(finished *mint.FinishedBody, hashedTranscript hash.Hash, mode string) error {
	finished2, err := p.getFinishedMsg(hashedTranscript, mode)
	if err != nil {
		return err
	}

	m1, err := finished.Marshal()
	if err != nil {
		return err
	}

	m2, err := finished2.Marshal()
	if err != nil {
		return err
	}

	if !hmac.Equal(m1, m2) {
		return common.ErrorInvalidFinishedMac
	}

	return nil
}

func getEmptyCert(context []byte) *mint.CertificateBody {
	return &mint.CertificateBody{CertificateRequestContext: context}
}

const contextLen int = 4

// GetRandomUnusedContext returns an unused random context.
// FUTURE: consider making this thread-safe by locking the state table.
func (p *Party) GetRandomUnusedContext() ([]byte, error) {
	var context []byte

	numTries := 0
	for numTries < 5 {
		context = make([]byte, contextLen)

		_, err := rand.Read(context)
		if err != nil {
			return nil, err
		}

		ok := p.validateContext(context)
		if !ok {
			numTries++
		} else {
			return context, nil
		}

	}
	return nil, common.ErrorInvalidContext

}

// Returns false if the context is the wrong length or already used.
// Should be used to check externally the provided context. There is no need to
// call it after GetRandomUnusedContext.
func (p *Party) validateContext(context []byte) bool {
	if len(context) != contextLen {
		return false
	}

	if _, used := p.getSession(context); used {
		return false
	}

	return true
}

// ExportedKeyGetterFromKeys takes in four keys and returns a function that
// returns the keys under the right circumstances
// Mainly used for testing.
func ExportedKeyGetterFromKeys(clientHandshakeContext, clientFinishedKey,
	serverHandshakeContext, serverFinishedKey []byte) ExportedKeyGetter {
	return func(mode, label string) ([]byte, error) {
		if mode == ClientAuthMode {
			if label == HandshakeLabel {
				return clientHandshakeContext, nil
			}

			if label == FinishedLabel {
				return clientFinishedKey, nil
			}
		}

		if mode == ServerAuthMode {
			if label == HandshakeLabel {
				return serverHandshakeContext, nil
			}

			if label == FinishedLabel {
				return serverFinishedKey, nil
			}
		}

		return nil, common.ErrorUnrecognizedLabel
	}
}
