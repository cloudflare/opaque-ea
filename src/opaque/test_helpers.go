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
	"reflect"

	"github.com/cloudflare/opaque-ea/src/common"
	"github.com/pkg/errors"
)

// TestMarshalUnmarshal is a test helper that errors if Marshal/Unmarshal
// for the type of data and empty is not working.
// data should be filled in and empty should be empty.
func TestMarshalUnmarshal(data, empty common.MarshalUnmarshaler) error {
	raw, err := data.Marshal()
	if err != nil {
		return errors.Wrap(err, "marshal")
	}

	bytesRead, err := empty.Unmarshal(raw)
	if err != nil {
		return errors.Wrap(err, "unmarshal")
	}

	if bytesRead != len(raw) {
		return errors.Errorf("incorrect unmarshal bytesRead: got %v, expected %v", bytesRead, len(raw))
	}

	if !reflect.DeepEqual(data, empty) {
		return errors.Errorf(common.ErrMarshalUnmarshalFailed, reflect.TypeOf(data), data, empty)
	}

	return nil
}
