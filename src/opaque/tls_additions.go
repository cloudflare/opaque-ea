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
	"crypto/x509"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
	"github.com/tatianab/mint/syntax"
)

// ProtocolVariant indicates which variant of OPAQUE we are using.
type ProtocolVariant byte

// We only implement OPAQUE-Sign.
const (
	OPAQUESign ProtocolVariant = 1 + iota
)

// These are chosen arbitrarily for now.
//  enum {
//       opaque_client_auth(TBD),
//       opaque_server_auth(TBD),
//      (65535)
// } ExtensionType;
// FUTURE: update once standardized.
const (
	ExtensionTypeOpaqueServerAuth mint.ExtensionType = 48
	ExtensionTypeOpaqueClientAuth mint.ExtensionType = 50

	OPAQUESIGNSignatureScheme mint.SignatureScheme = mint.ECDSA_P521_SHA512
)

// CertificateOPAQUESign is an alias for a mint Certificate.
// It is given a distinct name for the possibility of later
// being a separate type.
type CertificateOPAQUESign = mint.Certificate

// PAKEShareType indicates the type of PAKEShare.
type PAKEShareType byte

// Server/client indicates who created this PAKEShare.
const (
	PAKEShareTypeServer PAKEShareType = iota + 1
	PAKEShareTypeClient
)

// A PAKEShare is a collection of OPAQUE data.
// Should be included in a PAKEServerAuthExtension.
type PAKEShare interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) (int, error)
	Type() PAKEShareType
}

// A PAKEShareServer is a PAKEShare from the server containing OPRF data
// and the encrypted client credentials.
//
// struct {
// 	opaque identity<0..2^16-1>;
// 	opaque OPRF_2<1..2^16-1>;
// 	opaque vU<1..2^16-1>;   // omitted - not needed for OPAQUE-Sign
// 	opaque EnvU<1..2^16-1>; // should be: Envelope envelope;
// } PAKEShareServer;
//
//       2                        2
// | serverIDLen | serverID | oprfMsgLen | oprfMsg | envelope |.
type PAKEShareServer struct {
	// NOTE: the OPAQUE-TLS document says this should be UserID,
	// but we don't see why it should be echoed.
	ServerID []byte `tls:"head=2"`
	OprfMsg  []byte `tls:"head=2,min=1"`
	Envelope *Envelope
}

// Marshal returns the raw form of the PAKEShareServer struct.
func (pss *PAKEShareServer) Marshal() ([]byte, error) {
	return syntax.Marshal(pss)
}

// Unmarshal puts raw data into fields of a PAKEShareServer struct.
func (pss *PAKEShareServer) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, pss)
}

// Type returns the type of this struct: PAKEShareServer.
func (*PAKEShareServer) Type() PAKEShareType {
	return PAKEShareTypeServer
}

// PAKEShareClient is the core OPAQUE data sent by the client to request
// authentication from the server.
// Should be wrapped in a PAKEServerAuthExtension.
//
// struct {
// 	opaque identity<0..2^16-1>;
// 	opaque OPRF_1<1..2^16-1>;
// } PAKEShareClient;
//
//       2                    2
// | userIDLen | userID | oprfMsgLen | oprfMsg |.
type PAKEShareClient struct {
	UserID  []byte `tls:"head=2"`
	OprfMsg []byte `tls:"head=2,min=1"`
}

// Marshal returns the raw form of the PAKEShareClient struct.
func (psc *PAKEShareClient) Marshal() ([]byte, error) {
	return syntax.Marshal(psc)
}

// Unmarshal puts raw data into fields of a PAKEShareClient struct.
func (psc *PAKEShareClient) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, psc)
}

// Type returns the type of this struct: PAKEShareClient.
func (*PAKEShareClient) Type() PAKEShareType {
	return PAKEShareTypeClient
}

// PAKEServerAuthExtension is an extension that allows OPAQUE data to be
// attached to Exported Authenticator Requests and Exported Authenticators.
// It is for requests TO the server and EAs FROM the server.
// Implements mint.ExtensionBody.
//
// struct {
// 	select (Handshake.msg_type) {
// 	  ClientHello:					   // not used in OPAQUE-EA
// 		PAKEShareClient client_shares<0..2^16-1>;
// 		OPAQUEType types<0..2^16-1>;
// 	  EncryptedExtensions, Certificate:
// 		PAKEShareServer server_share;  // this can also be PAKEShareClient
// 		OPAQUEType type;
// 	} PAKEServerAuthExtension;
//
//                   1
// | pakeShare | opaqueType |.
type PAKEServerAuthExtension struct {
	PAKEShare  PAKEShare
	OPAQUEType ProtocolVariant
}

var _ mint.ExtensionBody = (*PAKEServerAuthExtension)(nil)

// SetFromList finds a PSAE in the given list of extensions and populates the given
// PSAE with the found data. Errors if list does not contain a PSAE extension.
func (psae *PAKEServerAuthExtension) SetFromList(el mint.ExtensionList) error {
	ok, err := el.Find(psae)
	if !ok || err != nil {
		return errors.Wrapf(common.ErrorNotFound, "pake server auth extension")
	}

	return nil
}

// Type returns the extension type.
func (psae *PAKEServerAuthExtension) Type() mint.ExtensionType {
	return ExtensionTypeOpaqueServerAuth
}

type pakeServerAuthExtensionInner struct {
	ServerShare *PAKEShareServer `tls:"optional"`
	ClientShare *PAKEShareClient `tls:"optional"`
	OPAQUEType  ProtocolVariant
}

// Marshal returns the raw form of the struct.
func (psae *PAKEServerAuthExtension) Marshal() ([]byte, error) {
	var clientShare *PAKEShareClient
	var serverShare *PAKEShareServer

	switch psae.PAKEShare.Type() {
	case PAKEShareTypeClient:
		clientShare = psae.PAKEShare.(*PAKEShareClient)
	case PAKEShareTypeServer:
		serverShare = psae.PAKEShare.(*PAKEShareServer)
	default:
		return nil, errors.New("unrecognized pake share type")
	}

	inner := &pakeServerAuthExtensionInner{
		ServerShare: serverShare,
		ClientShare: clientShare,
		OPAQUEType:  psae.OPAQUEType,
	}

	return syntax.Marshal(inner)
}

// Unmarshal puts raw data into fields of a struct.
func (psae *PAKEServerAuthExtension) Unmarshal(data []byte) (int, error) {
	inner := &pakeServerAuthExtensionInner{}

	bytesRead, err := syntax.Unmarshal(data, inner)
	if err != nil {
		return 0, err
	}

	var share PAKEShare
	if inner.ClientShare != nil && inner.ServerShare == nil {
		share = inner.ClientShare
	} else if inner.ServerShare != nil && inner.ClientShare == nil {
		share = inner.ServerShare
	}

	*psae = PAKEServerAuthExtension{
		PAKEShare:  share,
		OPAQUEType: inner.OPAQUEType,
	}

	return bytesRead, nil
}

// PAKEClientAuthExtension is an extension that allows OPAQUE data to be
// attached to Exported Authenticator.
// It is for requests TO the client.
// Implements mint.ExtensionBody.
//
// struct {
//	 opaque identity<0..2^16-1>;
// } PAKEClientAuthExtension;
//
//      2
// | userIDLen | userID |.
type PAKEClientAuthExtension struct {
	UserID []byte `tls:"head=2"`
}

var _ mint.ExtensionBody = (*PAKEClientAuthExtension)(nil)

// Type returns the extension type: PAKEClientAuthExtension.
func (pcae *PAKEClientAuthExtension) Type() mint.ExtensionType {
	return ExtensionTypeOpaqueClientAuth
}

// Marshal returns the raw form of the PAKEClientAuthExtension struct.
func (pcae *PAKEClientAuthExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(pcae)
}

// Unmarshal puts raw data into fields of a PAKEClientAuthExtension struct and
// returns the number of bytes read.
func (pcae *PAKEClientAuthExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, pcae)
}

// SetFromList finds a PCAE in the given list of extensions and populates the given
// PCAE with the found data. Errors if list does not contain a PCAE extension.
func (pcae *PAKEClientAuthExtension) SetFromList(el mint.ExtensionList) error {
	ok, err := el.Find(pcae)
	if !ok || err != nil {
		return errors.Wrapf(common.ErrorNotFound, "pake client auth extension")
	}

	return nil
}

// NewCertificateOPAQUESign returns a new OPAQUE-Sign certificate.
func NewCertificateOPAQUESign(privKey crypto.Signer) *CertificateOPAQUESign {
	_, x509cert, _ := mint.MakeNewSelfSignedCert("dummy", OPAQUESIGNSignatureScheme) // make the cert msg non-empty
	return &CertificateOPAQUESign{
		Chain:      []*x509.Certificate{x509cert},
		PrivateKey: privKey,
	}
}
