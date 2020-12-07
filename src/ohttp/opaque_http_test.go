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
	"io/ioutil"
	"log"
	"os"

	"testing"
	"time"

	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
)

func TestMain(m *testing.M) {
	// Turn off logging
	log.SetOutput(ioutil.Discard)
	os.Exit(m.Run())
}

func TestRunOpaqueOverHTTP(t *testing.T) {
	t.Skip("Does not work with proxies")
	go func() {
		err := RunOpaqueServer()
		if err != nil {
			t.Error(err)
		}
	}()

	cfg := setup()

	t.Run("Happy path", func(t *testing.T) {
		username := "new_user"
		password := "new_password"

		err := cfg.RunOpaqueRegisterClient(username, password)
		if err != nil {
			t.Error(err)
			return
		}

		getExportedKey, authHash, err := cfg.RequestExportedKeys()
		if err != nil {
			t.Error(err)
			return
		}

		err = cfg.RunOpaqueLoginClient(username, password, getExportedKey, authHash)
		if err != nil {
			t.Error(err)
			return
		}
	})

	t.Run("User not registered", func(t *testing.T) {
		username := "not_registered"
		password := "password"

		// skip registration

		getExportedKey, authHash, err := cfg.RequestExportedKeys()
		if err != nil {
			t.Error(err)
			return
		}

		err = cfg.RunOpaqueLoginClient(username, password, getExportedKey, authHash)
		if err == nil || !errors.Is(err, common.ErrorUserNotRegistered) {
			t.Errorf("expected error %s, got %s", common.ErrorUserNotRegistered, err)
			return
		}
	})

	t.Run("User already registered", func(t *testing.T) {
		username := "user1"
		password := "new_password"

		err := cfg.RunOpaqueRegisterClient(username, password)
		if err != nil {
			t.Error(err)
			return
		}

		err = cfg.RunOpaqueRegisterClient(username, password)
		if err == nil || !errors.Is(err, common.ErrorUserAlreadyRegistered) {
			t.Errorf("expected error %s, got %s", common.ErrorUserAlreadyRegistered, err)
			return
		}
	})

	t.Run("Bad password", func(t *testing.T) {
		username := "user1"
		password := "wrong"

		getExportedKey, authHash, err := cfg.RequestExportedKeys()
		if err != nil {
			t.Error(err)
			return
		}

		err = cfg.RunOpaqueLoginClient(username, password, getExportedKey, authHash)
		if err == nil || !errors.Is(err, common.ErrorBadEnvelope) {
			t.Errorf("expected error %s, got %s", common.ErrorBadEnvelope, err)
			return
		}
	})

	t.Run("Bad ciphersuite", func(t *testing.T) {
		username := "user42"
		password := "password"

		cfg.Ciphersuite = 0x00

		err := cfg.RunOpaqueRegisterClient(username, password)
		if err == nil || !errors.Is(err, common.ErrorUnsupportedCiphersuite) {
			t.Errorf("expected error %s, got %s", common.ErrorUnsupportedCiphersuite, err)
			return
		}
	})
}

func setup() *ClientConfig {
	time.Sleep(3 * time.Second) // wait for server to start

	return &ClientConfig{
		Domain:      "127.0.0.1:8080",
		Logger:      log.New(log.Writer(), "", 0),
		Ciphersuite: oprf.OPRFP256,
	}
}
