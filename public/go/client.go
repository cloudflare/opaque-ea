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

package main

import (
	"log"
	"strings"
	"syscall/js"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/ohttp"
)

var domain string

// RunLocalClient runs a local client.
func RunLocalClient() {
	run()
}

func run() {
	domain = ohttp.LocalDomain

	js.Global().Set("runOpaqueRegisterClient", js.FuncOf(runOpaqueRegisterClient))
	js.Global().Set("runOpaqueLoginClient", js.FuncOf(runOpaqueLoginClient))
	select {} // run indefinitely
}

// DOMWriter represents the div to write to.
type DOMWriter struct {
	divID string
}

func (dw *DOMWriter) Write(p []byte) (int, error) {
	split := strings.Split(string(p), "===")
	js.Global().Call("addBlock", split[0], split[1], dw.divID)
	return len(p), nil
}

func runOpaqueLoginClient(this js.Value, vals []js.Value) interface{} {
	username := vals[0].String()
	password := vals[1].String()
	divID := vals[2].String()

	go func() {
		cfg := setup(divID)

		getExportedKey, authHash, err := cfg.RequestExportedKeys()
		if err != nil {
			log.Println(err)
			return
		}

		err = cfg.RunOpaqueLoginClient(username, password, getExportedKey, authHash)
		if err != nil {
			cfg.AddError(err)
			log.Println(err)
			return
		}

		cfg.AddTitle(ohttp.SuccessLogin)
	}()

	return nil
}

func runOpaqueRegisterClient(this js.Value, vals []js.Value) interface{} {
	username := vals[0].String()
	password := vals[1].String()
	divID := vals[2].String()

	go func() {
		cfg := setup(divID)

		err := cfg.RunOpaqueRegisterClient(username, password)
		if err != nil {
			cfg.AddError(err)
			log.Println(err)
			return
		}

		cfg.AddTitle(ohttp.SuccessRegistration)
	}()

	return nil
}

func setup(divID string) *ohttp.ClientConfig {
	logger := log.New(&DOMWriter{divID: divID}, "", 0)

	return &ohttp.ClientConfig{
		Domain:      "opaque.research.cloudflare.com",
		Logger:      logger,
		Ciphersuite: oprf.OPRFP256,
	}
}
