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

package main

import (
	"github.com/IBM/cbomkit-theia/cmd"
	"log/slog"
	"os"
)

// Function used to set logging and start cobra
func main() {
	// Setup logging
	logHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: false,
	})
	logger := slog.New(logHandler)
	logger.Handler().WithAttrs([]slog.Attr{})
	slog.SetDefault(logger)

	// Run
	cmd.Execute()
}
