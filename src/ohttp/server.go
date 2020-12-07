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

// Adapted from public domain code:
// https://blog.kowalczyk.info/article/Jl3G/https-for-free-in-go.html

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/cloudflare/opaque-ea/src/expauth"
	"github.com/cloudflare/opaque-ea/src/opaque"
	"github.com/cloudflare/opaque-ea/src/opaqueea"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"golang.org/x/crypto/acme/autocert"
)

// RunOpaqueServer runs the OPAQUE server.
func RunOpaqueServer() error {
	log.Printf("Starting OPAQUE-over-HTTP Local Test Server...")

	var m *autocert.Manager
	var err error

	path := os.Getenv("PUBLIC_PATH")
	log.Printf("Public path: %s", path)

	domain := LocalDomain
	listenAddr := LocalDomain
	httpSrv, err := makeHTTPServer(path, domain, true)
	if err != nil {
		return err
	}

	// allow autocert handle Let's Encrypt callbacks over http
	if m != nil {
		httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
	}

	httpSrv.Addr = listenAddr
	log.Printf("Starting HTTP server on %s\n", listenAddr)

	err = httpSrv.ListenAndServe()
	if err != nil {
		log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
	}

	return nil
}

// spaHandler implements the http.Handler interface, so we can use it
// to respond to HTTP requests. The path to the static directory and
// path to the index file within that static directory are used to
// serve the SPA in the given static directory.
type spaHandler struct {
	staticPath string
	indexPath  string
}

func (h spaHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	// get the absolute path to prevent directory traversal
	path, err := filepath.Abs(r.URL.Path)
	if err != nil {
		// if we failed to get the absolute path respond with a 400 bad request
		// and stop
		writeError(w, err, http.StatusBadRequest)
		return
	}

	// prepend the path with the path to the static directory
	path = filepath.Join(h.staticPath, path)

	// check whether a file exists at the given path
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		// file does not exist, serve index.html
		http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		return
	} else if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	// otherwise, use http.FileServer to serve the static dir
	http.FileServer(http.Dir(h.staticPath)).ServeHTTP(w, r)
}

func makeServerFromRouter(rtr *mux.Router, isLocal bool) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	if isLocal {
		// See: https://github.com/rs/cors
		// https://flaviocopes.com/golang-enable-cors/
		handler := cors.Default().Handler(rtr)
		return &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      handler,
		}
	}

	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      rtr,
	}
}

func makeHTTPServer(path, domain string, isLocal bool) (*http.Server, error) {
	rtr := mux.NewRouter()
	spa := spaHandler{staticPath: path, indexPath: "index.html"}
	rtr.HandleFunc("/", spa.handleIndex)
	rtr.HandleFunc("/script.js", spa.handleIndex)
	rtr.HandleFunc("/wasm_exec.js", spa.handleIndex)
	rtr.HandleFunc("/main.wasm", spa.handleIndex)

	log.Println("Creating local server configuration")
	opaqueAuth := OPAQUEAuth{}
	err := opaqueAuth.Populate(domain)
	if err != nil {
		return nil, err
	}
	log.Printf("Local server configuration: %v", opaqueAuth.cfg.OpaqueCfg)

	rtr.HandleFunc(configEndpoint, opaqueAuth.HandleConfigRequest)
	rtr.HandleFunc(exporterKeyTestEndpoint, opaqueAuth.HandleExportedKeyTestRequest)
	rtr.HandleFunc(exporterKeyEndpoint, opaqueAuth.HandleExportedKeyRequest)
	rtr.HandleFunc(registerRequestEndpoint, opaqueAuth.HandleRegistrationRequest)
	rtr.HandleFunc(registerFinalizeEndpoint, opaqueAuth.HandleRegistrationUpload)
	rtr.HandleFunc(loginRequestEndpoint, opaqueAuth.HandleAuthRequest)
	rtr.HandleFunc(loginFinalizeEndpoint, opaqueAuth.HandleAuthResponse)

	return makeServerFromRouter(rtr, isLocal), nil
}

func makeHTTPToHTTPSRedirectServer() *http.Server {
	handleRedirect := func(w http.ResponseWriter, r *http.Request) {
		newURI := "https://" + r.Host + r.URL.String()
		http.Redirect(w, r, newURI, http.StatusFound)
	}
	rtr := mux.NewRouter()

	rtr.HandleFunc("/", handleRedirect)

	return makeServerFromRouter(rtr, false)
}

// OPAQUEAuth represents an OPAQUE authentication struct.
type OPAQUEAuth struct {
	cfg      *opaqueea.ServerConfig
	sessions map[string]*opaqueea.Server
}

// Populate populates the OPAQUEAuth with the needed fields.
func (oa *OPAQUEAuth) Populate(domain string) error {
	cfg, err := opaque.NewServerConfig(domain, oprf.OPRFP256)
	if err != nil {
		return err
	}

	oa.cfg = &opaqueea.ServerConfig{OpaqueCfg: cfg}
	oa.sessions = make(map[string]*opaqueea.Server)

	return nil
}

// AddSession adds a session to the OPAQUEAuth.
func (oa *OPAQUEAuth) AddSession(ctx []byte, session *opaqueea.Server) error {
	if _, used := oa.sessions[string(ctx)]; !used {
		oa.sessions[string(ctx)] = session
		return nil
	}

	return errors.New("session with context already active")
}

// NewSession creates a new session and adds it to the OPAQUE Auth.
func (oa *OPAQUEAuth) NewSession(ctx []byte, connState *tls.ConnectionState) (*opaqueea.Server, error) {
	var eaState *expauth.Party

	if connState == nil {
		getExportedKey, authHash := expauth.GetTestGetterAndHash()
		eaState = expauth.ServerFromGetter(getExportedKey, authHash)
	} else {
		eaState = expauth.ServerFromTLSConnState(connState)
	}

	session, err := opaqueea.NewServer(eaState, oa.cfg)
	if err != nil {
		return nil, err
	}

	err = oa.AddSession(ctx, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// RetrieveSession retrieves a session from the OPAQUE Auth.
func (oa *OPAQUEAuth) RetrieveSession(ctx []byte) (*opaqueea.Server, error) {
	session, ok := oa.sessions[string(ctx)]
	if !ok {
		return nil, errors.New("session not found")
	}

	return session, nil
}

// CloseSession closes/deletes a session from the OPAQUE Auth.
func (oa *OPAQUEAuth) CloseSession(ctx []byte) {
	delete(oa.sessions, string(ctx))
}

// HandleConfigRequest handles a request for config.
func (oa *OPAQUEAuth) HandleConfigRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling request for config...")

	response := opaqueea.ConfigMaterial{Suite: oa.cfg.OpaqueCfg.Suite}
	rawResponse, err := json.Marshal(response)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	log.Println("Client request OK. Sending server response...")

	_, err = w.Write(rawResponse)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
}

// HandleExportedKeyTestRequest handles an exported key test request.
func (oa *OPAQUEAuth) HandleExportedKeyTestRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling request for TEST exported keys...")

	response, err := opaqueea.GetTestExportedKeyMaterial()
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	handleExportedKeyRequestInner(response, w)
}

// HandleExportedKeyRequest handles an exported key request.
func (oa *OPAQUEAuth) HandleExportedKeyRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling request for exported keys...")

	response, err := opaqueea.GetExportedKeyMaterial(req)
	if err != nil {
		log.Println(err)
		writeError(w, err, http.StatusBadRequest)
		return
	}

	handleExportedKeyRequestInner(response, w)
}

func handleExportedKeyRequestInner(response *opaqueea.ExportedKeyMaterial, w http.ResponseWriter) {
	rawResponse, err := json.Marshal(response)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	log.Println("Client request OK. Sending server response...")

	_, err = w.Write(rawResponse)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
}

// HandleRegistrationRequest handles a registration request.
func (oa *OPAQUEAuth) HandleRegistrationRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling registration request...")

	msg, sessionID, err := httpRequestToMsg(req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	log.Println("Creating a new session...")
	session, err := oa.NewSession(sessionID, req.TLS)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	log.Println("Getting the registration response...")
	response, err := session.RegistrationResponse(msg)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	rawResponse, err := response.Marshal()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	log.Println("Client request OK. Sending server response...")

	_, err = w.Write(rawResponse)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
	}
}

// HandleRegistrationUpload handles a registration upload.
func (oa *OPAQUEAuth) HandleRegistrationUpload(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling registration upload...")

	msg, sessionID, err := httpRequestToMsg(req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	session, err := oa.RetrieveSession(sessionID)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	defer oa.CloseSession(sessionID)

	err = session.UploadCredentials(msg)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	log.Println("Registration successful.")
}

// HandleAuthRequest handles an auth request.
func (oa *OPAQUEAuth) HandleAuthRequest(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling authentication request...")

	msg, sessionID, err := httpRequestToMsg(req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	session, err := oa.NewSession(sessionID, req.TLS)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	response, err := session.Respond(msg)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	rawResponse, err := response.Marshal()
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}

	log.Println("Client request OK. Sending server response...")

	_, err = w.Write(rawResponse)
	if err != nil {
		writeError(w, err, http.StatusInternalServerError)
		return
	}
}

// HandleAuthResponse handles an auth response.
func (oa *OPAQUEAuth) HandleAuthResponse(w http.ResponseWriter, req *http.Request) {
	log.Println("Handling client authenticator...")

	msg, sessionID, err := httpRequestToMsg(req)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	session, err := oa.RetrieveSession(sessionID)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	defer oa.CloseSession(sessionID)

	err = session.Verify(msg)
	if err != nil {
		writeError(w, err, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)

	log.Println("Login accepted.")
}

func httpRequestToMsg(resp *http.Request) (*opaqueea.ProtocolMessage, []byte, error) {
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "read body")
	}

	msg := &HTTPMessage{}

	err = json.Unmarshal(raw, msg)
	if err != nil {
		return nil, nil, err
	}

	sessionID := msg.RequestID
	msgBody := &opaqueea.ProtocolMessage{}

	_, err = msgBody.Unmarshal(msg.RequestBody)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "unmarshal")
	}

	return msgBody, sessionID, nil
}

func writeError(w http.ResponseWriter, cause error, httpCode int) {
	log.Printf("writeError: %s\n", cause)

	rawErr, err := common.MarshalErrorAsJSON(cause)
	if err != nil {
		log.Printf("Error marshaling JSON: %s\n", err)

		// recover by sending generic error
		rawErr, _ = json.Marshal(common.ErrorOtherError)
	}

	jsonString := fmt.Sprintf("{\"error\":%s}", rawErr)

	http.Error(w, jsonString, httpCode)
}
