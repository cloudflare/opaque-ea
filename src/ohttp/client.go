// Copyright (c) 2020, Cloudflare. All rights reserved.
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

package ohttp

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"

	"io/ioutil"
	"log"
	"net/http"

	"github.com/cloudflare/circl/oprf"
	"github.com/pkg/errors"
	"github.com/tatianab/mint"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
	"github.com/cloudflare/opaque-ea/src/opaqueea"
)

// ClientConfig represents a client configuration for http.
type ClientConfig struct {
	Domain      string
	Ciphersuite oprf.SuiteID
	Logger      *log.Logger
}

// RequestCiphersuite request a ciphersuite for a Client.
func (c *ClientConfig) RequestCiphersuite() error {
	c.AddTitle("Requesting OPAQUE ciphersuite...")

	serverHTTPResponse, err := c.Get(configEndpoint)
	if err != nil {
		return err
	}

	err = c.ParseConfigMsg(serverHTTPResponse)
	if err != nil {
		return err
	}

	return nil
}

// ParseConfigMsg parses the config message for a Client.
func (c *ClientConfig) ParseConfigMsg(r *http.Response) error {
	defer r.Body.Close()

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	response := &opaqueea.ConfigMaterial{}

	err = json.Unmarshal(raw, response)
	if err != nil {
		return err
	}

	c.AddMessage("Parsing OPAQUE config", response)

	if c.Ciphersuite == 0x00 {
		return common.ErrorUnsupportedCiphersuite
	}

	c.Ciphersuite = response.Suite

	return nil
}

// RequestExportedKeys requests the exported keys.
func (c *ClientConfig) RequestExportedKeys() (expauth.ExportedKeyGetter, crypto.Hash, error) {
	endpoint := exporterKeyTestEndpoint

	c.AddTitle("Requesting exporter keys...")

	serverHTTPResponse, err := c.Get(endpoint)
	if err != nil {
		return nil, 0, err
	}

	getExportedKey, authHash, err := c.ParseExporterKeyMsg(serverHTTPResponse)
	if err != nil {
		return nil, 0, err
	}

	return getExportedKey, authHash, nil
}

// ParseExporterKeyMsg parses into a ExportedKey.
func (c *ClientConfig) ParseExporterKeyMsg(r *http.Response) (expauth.ExportedKeyGetter, crypto.Hash, error) {
	defer r.Body.Close()

	raw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, 0, err
	}

	response := &opaqueea.ExportedKeyMaterial{}

	err = json.Unmarshal(raw, response)
	if err != nil {
		return nil, 0, err
	}

	c.AddMessage("Parsing exporter keys", response)

	getExportedKey, authHash := response.ToGetterAndHash()

	return getExportedKey, authHash, nil
}

// RunOpaqueRegisterClient runs an opaque register client.
func (c *ClientConfig) RunOpaqueRegisterClient(username, password string) error {
	client, err := c.SetupClient(username, nil, 0)
	if err != nil {
		return err
	}

	sessionID := common.GetRandomBytes(SessionIDLength)

	httpResponse, err := c.SendRegisterRequest(client, sessionID, password)
	if err != nil {
		return err
	}

	defer httpResponse.Body.Close()

	httpResponse2, err := c.SendRegisterResponse(client, sessionID, httpResponse)
	if err != nil {
		return err
	}

	defer httpResponse2.Body.Close()

	if httpResponse2.StatusCode != http.StatusOK {
		return errors.New("server registration error")
	}

	return nil
}

// RunOpaqueLoginClient runs an opaque login client.
func (c *ClientConfig) RunOpaqueLoginClient(username, password string, getExportedKey expauth.ExportedKeyGetter,
	authHash crypto.Hash) error {
	client, err := c.SetupClient(username, getExportedKey, authHash)
	if err != nil {
		return err
	}

	sessionID := common.GetRandomBytes(SessionIDLength)

	httpResponse, err := c.SendLoginRequest(client, sessionID, password)
	if err != nil {
		return err
	}

	defer httpResponse.Body.Close()

	httpResponse2, err := c.SendLoginResponse(client, sessionID, httpResponse)
	if err != nil {
		return err
	}

	defer httpResponse2.Body.Close()

	if httpResponse2.StatusCode != http.StatusOK {
		return errors.New("server login error")
	}

	return nil
}

// SetupClient sets up a client.
func (c *ClientConfig) SetupClient(username string, getExportedKey expauth.ExportedKeyGetter,
	authHash crypto.Hash) (*opaqueea.Client, error) {
	eaClient := expauth.ClientFromGetter(getExportedKey, authHash)

	if c.Ciphersuite == 0x00 {
		err := c.RequestCiphersuite()
		if err != nil {
			return nil, err
		}
	}

	client, err := opaqueea.NewClient(eaClient, username, c.Domain, c.Ciphersuite)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// SendRegisterRequest sends a client register request.
func (c *ClientConfig) SendRegisterRequest(client *opaqueea.Client, sessionID []byte, password string) (*http.Response, error) {
	// TODO: consider whether password should be (username || password) to avoid user confusion
	signer, err := mint.NewSigningKey(opaque.OPAQUESIGNSignatureScheme)
	if err != nil {
		return nil, err
	}

	request, err := client.RegistrationRequest(password, signer)
	if err != nil {
		return nil, err
	}

	raw, err := c.packageMessage(sessionID, request)
	if err != nil {
		return nil, err
	}

	httpResponse, err := c.Post(registerRequestEndpoint, raw)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Client registration request sent", request)

	return httpResponse, nil
}

// SendRegisterResponse sends a client register response.
func (c *ClientConfig) SendRegisterResponse(client *opaqueea.Client, sessionID []byte, httpResponse *http.Response) (*http.Response, error) {
	serverResponse, err := c.httpResponseToMsg(httpResponse)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Received server registration response", serverResponse)

	clientResponse, err := client.FinalizeRegistration(serverResponse)
	if err != nil {
		return nil, err
	}

	raw, err := c.packageMessage(sessionID, clientResponse)
	if err != nil {
		return nil, err
	}

	httpResponse2, err := c.Post(registerFinalizeEndpoint, raw)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Client credential upload sent", clientResponse)

	return httpResponse2, nil
}

// SendLoginRequest sends a login request.
func (c *ClientConfig) SendLoginRequest(client *opaqueea.Client, sessionID []byte, password string) (*http.Response, error) {
	request, err := client.Request(password)
	if err != nil {
		return nil, err
	}

	raw, err := c.packageMessage(sessionID, request)
	if err != nil {
		return nil, err
	}

	httpResponse, err := c.Post(loginRequestEndpoint, raw)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Client login request sent", request)

	return httpResponse, nil
}

// SendLoginResponse sends a client login response.
func (c *ClientConfig) SendLoginResponse(client *opaqueea.Client, sessionID []byte, httpResponse *http.Response) (*http.Response, error) {
	serverResponse, err := c.httpResponseToMsg(httpResponse)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Received server login response", serverResponse)

	clientResponse, err := client.VerifyAndRespond(serverResponse)
	if err != nil {
		return nil, err
	}

	raw, err := c.packageMessage(sessionID, clientResponse)
	if err != nil {
		return nil, err
	}

	httpResponse2, err := c.Post(loginFinalizeEndpoint, raw)
	if err != nil {
		return nil, err
	}

	c.AddMessage("Client authenticator sent", clientResponse)

	return httpResponse2, nil
}

// Get gets an http Response.
func (c *ClientConfig) Get(endpoint string) (*http.Response, error) {
	prefix := httpsPrefix

	httpResponse, err := http.Get(fmt.Sprintf("%s%s%s", prefix, c.Domain, endpoint))
	if err != nil {
		return nil, err
	}

	return httpResponse, nil
}

// Post gets an http post response.
func (c *ClientConfig) Post(endpoint string, request []byte) (*http.Response, error) {
	prefix := httpsPrefix

	httpResponse, err := http.Post(fmt.Sprintf("%s%s%s", prefix, c.Domain, endpoint), "application/json", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	return httpResponse, nil
}

func (c *ClientConfig) httpResponseToMsg(resp *http.Response) (*opaqueea.ProtocolMessage, error) {
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check if message is an error
	if resp.StatusCode != http.StatusOK {
		var jsonMap map[string]uint8

		err = json.Unmarshal(raw, &jsonMap)
		if err != nil {
			return nil, errors.Errorf("server error occurred but json %s could not be unmarshaled: %s", raw, err)
		}

		if code, ok := jsonMap["error"]; ok {
			serverError := common.Error(code)
			return nil, serverError
		}

		return nil, errors.Errorf("server error occurred but json %s malformed", raw)
	}

	msg := &opaqueea.ProtocolMessage{}

	_, err = msg.Unmarshal(raw)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (c *ClientConfig) packageMessage(sessionID []byte, body common.Marshaler) ([]byte, error) {
	rawBody, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	msg := &HTTPMessage{
		RequestID:   sessionID,
		RequestBody: rawBody,
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

// AddError adds a library error.
func (c *ClientConfig) AddError(err error) {
	errString := ErrorGeneric

	switch {
	case errors.Is(err, common.ErrorBadEnvelope):
		errString = ErrorBadPasswordLikely
	case errors.Is(err, common.ErrorUserNotRegistered):
		errString = ErrorUsernameNotRegistered
	case errors.Is(err, common.ErrorUserAlreadyRegistered):
		errString = ErrorUsernameTaken
	}

	c.AddTitle(errString)
}

// AddTitle adds a title to the string.
func (c *ClientConfig) AddTitle(title string) {
	c.Logger.Printf("%s%s%s", title, "===", "")
}

// AddMessage adds a message to the DOM.
func (c *ClientConfig) AddMessage(title string, msg interface{}) {
	jsonMsg, err := json.MarshalIndent(msg, "", "  ")
	if err != nil {
		log.Println("Could not add message to DOM.")
		return
	}

	c.Logger.Printf("%s...%s%s", title, "===", jsonMsg)
}
