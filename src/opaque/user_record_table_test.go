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
	"testing"

	"github.com/cloudflare/opaque-ea/src/common"

	"github.com/cloudflare/circl/oprf"
	"github.com/pkg/errors"
)

func TestInMemoryUserRecordTable(t *testing.T) {
	testUser := "user1"

	cfg, err := NewTestServerConfig("hello.com", oprf.OPRFP256)
	if err != nil {
		t.Error(err)
		return
	}

	// Lookup a user
	_, err = cfg.RecordTable.LookupUserRecord(testUser)
	if err != nil {
		t.Error(err)
		return
	}

	// Add a new user and look up
	err = cfg.RecordTable.InsertUserRecord("im_a_new_user", &UserRecord{})
	if err != nil {
		t.Error(err)
		return
	}

	_, err = cfg.RecordTable.LookupUserRecord("im_a_new_user")
	if err != nil {
		t.Error(err)
		return
	}

	// Try to add a user who is already there
	err = cfg.RecordTable.InsertUserRecord(testUser, &UserRecord{})

	if !errors.Is(err, common.ErrorUserAlreadyRegistered) {
		t.Errorf("expected err %v to contain %v", err, common.ErrorUserAlreadyRegistered)
		return
	}

	// Try to lookup a user who is not there
	_, err = cfg.RecordTable.LookupUserRecord("not a user")

	if !errors.Is(err, common.ErrorUserNotRegistered) {
		t.Errorf("expected err %v to contain %v", err, common.ErrorUserNotRegistered)
		return
	}
}
