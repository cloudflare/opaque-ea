package opaque

import (
	"encoding/json"
)

func (pmt ProtocolMessageType) String() string {
	return ProtocolMessageTypeToStringMap[pmt]
}

// ProtocolMessageTypeToStringMap maps the Protocol Message Type to its string equivalent.
var ProtocolMessageTypeToStringMap = map[ProtocolMessageType]string{
	ProtocolMessageTypeRegistrationRequest:  "OPAQUE Registration Request",
	ProtocolMessageTypeRegistrationResponse: "OPAQUE Registration Response",
	ProtocolMessageTypeRegistrationUpload:   "OPAQUE Registration Upload",
	ProtocolMessageTypeCredentialRequest:    "OPAQUE Credential Request",
	ProtocolMessageTypeCredentialResponse:   "OPAQUE Credential Response",
}

type registrationRequestJSON struct {
	UserID   string
	OprfData []byte
}

// MarshalJSON encodes the RegistrationRequest.
func (rr *RegistrationRequest) MarshalJSON() ([]byte, error) {
	rrJSON := &registrationRequestJSON{
		UserID:   string(rr.UserID),
		OprfData: rr.OprfData,
	}

	return json.Marshal(rrJSON)
}

// String returns the string equivalent of the Credential Type.
func (ct CredentialType) String() string {
	switch ct {
	case CredentialTypeUserPrivateKey:
		return "User Private Key"
	case CredentialTypeUserPublicKey:
		return "User Public Key"
	case CredentialTypeServerPublicKey:
		return "Server Public Key"
	case CredentialTypeUserIdentity:
		return "User Identity"
	case CredentialTypeServerIdentity:
		return "Server Identity"
	}

	return "Unrecognized Credential Type"
}

// MarshalText encodes the Credential Type.
func (ct CredentialType) MarshalText() ([]byte, error) {
	return []byte(ct.String()), nil
}
