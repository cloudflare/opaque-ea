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

package common

import (
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

// Error represents an error for the library.
type Error uint8

const (
	// ErrorNoError represents an empty error.
	ErrorNoError Error = 0 + iota

	// ErrorSpontaneousAuthForbidden represents error when an spontaneous session is forbidden.
	ErrorSpontaneousAuthForbidden
	// ErrorSessionNotFound represents error when the session is not found.
	ErrorSessionNotFound
	// ErrorIncorrectState represents error it reaches an incorrect state.
	ErrorIncorrectState
	// ErrorIncorrectRole represents error when it reaches an incorrect role.
	ErrorIncorrectRole
	// ErrorUnrecognizedMessage represents error when the message is not recognized.
	ErrorUnrecognizedMessage
	// ErrorNoCertificates represents error when there are no certificates.
	ErrorNoCertificates
	// ErrorInconsistentContext represents error when the context is inconsistent.
	ErrorInconsistentContext
	// ErrorReusedContext represents error when context is reused.
	ErrorReusedContext
	// ErrorInvalidContext represents error when the context is invalid.
	ErrorInvalidContext
	// ErrorUnrecognizedLabel represents error when the label is not recognized.
	ErrorUnrecognizedLabel
	// ErrorNoPasswordTable represents error when there is no password table.
	ErrorNoPasswordTable
	// ErrorUserNotRegistered represents error when the user is not yet registered.
	ErrorUserNotRegistered
	// ErrorUserAlreadyRegistered represents error when the user is already registered.
	ErrorUserAlreadyRegistered
	// ErrorUnexpectedMessage represents error when an unexpected message arrives.
	ErrorUnexpectedMessage
	// ErrorHmacTagInvalid represents error when HMAC tag is invalid.
	ErrorHmacTagInvalid
	// ErrorForbiddenPolicy represents error when there is a forbidden credential encoding policy.
	ErrorForbiddenPolicy
	// ErrorUnexpectedData represents error when unexpected data arrived.
	ErrorUnexpectedData
	// ErrorInvalidFinishedMac represents error when the finished MAC is invalid.
	ErrorInvalidFinishedMac
	// ErrorBadEnvelope represents error when decription of the envelope fails.
	ErrorBadEnvelope
	// ErrorInvalidAuthenticator represents error when the authenticator is invalid.
	ErrorInvalidAuthenticator
	// ErrorUnsupportedCiphersuite represents error when the ciphersuite is not supported.
	ErrorUnsupportedCiphersuite
	// ErrorNotFound represents error when a field is not found.
	ErrorNotFound

	// ErrorOtherError represents other kinds of errors not previously covered.
	ErrorOtherError
)

// Error returns the corresponding string to the error.
func (e Error) Error() string {
	return alertToString[e]
}

// Is compares two errors.
func (e Error) Is(target error) bool {
	return e == target.(Error)
}

// Wrap coverts an stdlib error to a library one.
func (e Error) Wrap(err error) error {
	if err == nil {
		return nil
	}

	err = &withError{
		cause: err,
		err:   e,
	}

	return errors.WithStack(err)
}

type withError struct {
	cause error
	err   error
}

// Error returs the string associated with the error with cause.
func (we *withError) Error() string {
	return fmt.Sprintf("%s: %s", we.err, we.cause)
}

func (we *withError) Is(target error) bool {
	return errors.Is(we.cause, target) || errors.Is(we.err, target)
}

func (we *withError) Cause() error {
	return we.cause
}

func (we *withError) Unwrap() error {
	return we.cause
}

// Get error code from latest Error
func (we *withError) MarshalJSON() ([]byte, error) {
	if latestErr, ok := we.err.(Error); ok {
		return json.Marshal(latestErr)
	}

	if err, ok := errors.Cause(we).(Error); ok {
		return json.Marshal(err)
	}

	return json.Marshal(ErrorOtherError)
}

// Causer is an interface for the cause of an error.
type Causer interface {
	Cause() error
}

// MarshalErrorAsJSON marshals an error as json.
func MarshalErrorAsJSON(target error) ([]byte, error) {
	switch t := target.(type) {
	case Error, *withError:
		return json.Marshal(t)
	case Causer:
		return MarshalErrorAsJSON(t.Cause())
	}

	return json.Marshal(ErrorOtherError)
}

var alertToString = map[Error]string{
	ErrorSpontaneousAuthForbidden: "client cannot authenticate spontaneously",
	ErrorSessionNotFound:          "session not found",
	ErrorIncorrectState:           "session in incorrect state",
	ErrorIncorrectRole:            "incorrect role for action",
	ErrorUnrecognizedMessage:      "unrecognized message",
	ErrorNoCertificates:           "no certificates",
	ErrorInconsistentContext:      "contexts do not match",
	ErrorInvalidContext:           "invalid context",
	ErrorUnrecognizedLabel:        "unrecognized mode/label",
	ErrorNoPasswordTable:          "no record table",
	ErrorUserNotRegistered:        "user is not registered",
	ErrorUserAlreadyRegistered:    "user already registered",
	ErrorUnexpectedMessage:        "unrecognized protocol message",
	ErrorHmacTagInvalid:           "hmac verification failed, tags not equal",
	ErrorForbiddenPolicy:          "forbidden credential encoding policy",
	ErrorUnexpectedData:           "unexpected data",
	ErrorInvalidFinishedMac:       "finished MACs not equal",
	ErrorBadEnvelope:              "decrypt envelope failed",
	ErrorInvalidAuthenticator:     "invalid client exported authenticator",
	ErrorUnsupportedCiphersuite:   "unsupported ciphersuite",
	ErrorNotFound:                 "not found",
}

// Test strings
const (
	ErrMarshalUnmarshalFailed = "marshal unmarshal %v failed: \nexpected %#v,\ngot %#v"
)
