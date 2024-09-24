// Copyright 2024 IBM
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package errors

import (
	"errors"
	"fmt"
)

// ErrInsufficientInformation Error
// to represent cases in which a plugin had to interrupt its execution due to missing information
// (e.g., in the BOM or in the filesystem)
var ErrInsufficientInformation = errors.New("scanner: insufficient information to continue")

// GetInsufficientInformationError Error to represent cases in which a plugin had
// to interrupt its execution due to missing information (e.g., in the BOM or in the filesystem)
func GetInsufficientInformationError(msg string, plugin string, affectedObjectType string, affectedObjectName string) error {
	return fmt.Errorf("%w: (%v:%v:%v) %v", ErrInsufficientInformation, plugin, affectedObjectType, affectedObjectName, msg)
}

// ErrParsingFailedAlthoughChecked Error
// to represent cases in which parsing of a relevant file failed although the plugin verified the file beforehand;
// this error might suggest a bug
var ErrParsingFailedAlthoughChecked = errors.New("scanner: failed to parse file that was assumed to be a valid configuration")

// GetParsingFailedAlthoughCheckedError Error to represent cases in which parsing of a relevant file failed
// although the plugin verified the file beforehand;
// this error might suggest a bug
func GetParsingFailedAlthoughCheckedError(parsingError error, plugin string) error {
	return fmt.Errorf("%w: (%v) %w", ErrParsingFailedAlthoughChecked, plugin, parsingError)
}
