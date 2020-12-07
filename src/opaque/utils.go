package opaque

import (
	"crypto"
	"fmt"

	"github.com/cloudflare/circl/oprf"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"
)

// RunLocalOPRF returns the randomized password for the given server, username and
// password.
// It runs the OPRF protocol locally with a dummy client.
// Only for testing - in a real setting the server does not know the password.
func RunLocalOPRF(s *Server, username, password string) ([]byte, error) {
	client, err := NewClient(username, s.Config.ServerID, s.Config.Suite)
	if err != nil {
		return nil, errors.Wrap(err, "new client")
	}

	oprf1, err := client.blind(password)
	if err != nil {
		return nil, errors.Wrap(err, "blind")
	}

	oprfServer, err := oprf.NewServer(s.Config.Suite, nil)
	if err != nil {
		return nil, err
	}

	s.UserRecord.OprfState = oprfServer
	oprf2, err := s.evaluate(oprf1)
	if err != nil {
		return nil, errors.Wrap(err, "evaluate")
	}

	rwd, err := client.finalizeHarden(oprf2)
	if err != nil {
		return nil, errors.Wrap(err, "unblind finalize harden")
	}

	s.UserRecord.UserID = []byte(username)
	s.UserRecord.OprfState = oprfServer

	return rwd, nil
}

// GetTestUserRecord returns a new test user record for the given domain,
// username and password.
// It should be used for testing.
func GetTestUserRecord(s *Server, username, password string) (*UserRecord, error) {
	rwd, err := RunLocalOPRF(s, username, password)
	if err != nil {
		return nil, errors.Wrap(err, "run local oprf")
	}

	userPrivKey, _, _ := mint.MakeNewSelfSignedCert(username, OPAQUESIGNSignatureScheme)

	creds, err := newTestCredentials(userPrivKey, s.Config.Signer.Public(), s.Config.ServerID)
	if err != nil {
		return nil, errors.Wrap(err, "new test creds")
	}

	nonceLen := int(32)
	envelope, exportedKey, err := EncryptCredentials(rwd, creds, nonceLen)
	if err != nil {
		return nil, errors.Wrap(err, "encrypt credentials")
	}

	if len(exportedKey) == 0 {
		return nil, errors.New("exportedKey not set")
	}

	return s.InsertNewUserRecord(userPrivKey.Public(), envelope)
}

// GetTestUserRecords returns numRecords dummy user records with unique usernames
// and passwords: (user1, password1),...,(userN,...,passwordN).
// It should be used for testing.
func GetTestUserRecords(serverSigner crypto.Signer, numRecords int, domain string, suite oprf.SuiteID) (records []*UserRecord, err error) {
	records = make([]*UserRecord, numRecords)

	for i := 0; i < numRecords; i++ {
		username := fmt.Sprintf("user%v", i)
		password := fmt.Sprintf("password%v", i)

		s, err := NewServer(
			&ServerConfig{
				Signer:   serverSigner,
				ServerID: domain,
				Suite:    suite,
			})
		if err != nil {
			return nil, errors.Wrap(err, "new server")
		}

		record, err := GetTestUserRecord(s, username, password)
		if err != nil {
			return nil, errors.Wrap(err, "test user record")
		}

		records[i] = record
	}

	return records, nil
}

// NewTestServerConfig returns a ServerConfig struct containing a test record
// table of the desired size, with dummy usernames and user records, and a
// function to get a user record from a username. Credentials
// are (user1, password1)...(userN,passwordN).
// It should be used for testing.
func NewTestServerConfig(domain string, suite oprf.SuiteID) (cfg *ServerConfig, err error) {
	signer, err := mint.NewSigningKey(OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	t := NewInMemoryUserRecordTable()

	n := 3
	records, err := GetTestUserRecords(signer, n, domain, suite)
	if err != nil {
		return nil, errors.Wrap(err, "test user records")
	}

	err = t.BulkAdd(records)
	if err != nil {
		return nil, errors.Wrap(err, "bulk add")
	}

	return &ServerConfig{
		ServerID:    domain,
		Signer:      signer,
		RecordTable: t,
		Suite:       suite,
	}, nil
}
