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

package cyclonedx

import (
	"bytes"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/exp/slog"
)

// Write bom to the file
func WriteBOM(bom *cdx.BOM, file *os.File) error {
	// Encode the BOM
	err := cdx.NewBOMEncoder(file, cdx.BOMFileFormatJSON).
		SetPretty(true).
		Encode(bom)
	if err != nil {
		return err
	}
	return nil
}

// Parse and validate a CycloneDX BOM from path using the schema under schemaPath
func ParseBOM(path string, schemaPath string) (*cdx.BOM, error) {
	// Read BOM
	slog.Info("Reading BOM file", "path", path)
	dat, err := os.ReadFile(path)
	if err != nil {
		return new(cdx.BOM), err
	}

	slog.Info("Validating BOM file using schema", "path", path, "schema", schemaPath)
	// JSON Validation via Schema
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	documentLoader := gojsonschema.NewStringLoader(string(dat))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return new(cdx.BOM), err
	}

	if result.Valid() {
		slog.Info("Provided BOM is valid.")
	} else {
		slog.Error("The BOM is not valid. see errors:")
		for _, desc := range result.Errors() {
			fmt.Fprintf(os.Stderr, "- %s\n", desc)
		}
		return new(cdx.BOM), fmt.Errorf("provider: bom is not valid due to schema %v", schemaPath)
	}

	// Decode BOM from JSON
	slog.Info("Decoding BOM from JSON to GO object")
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(dat), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	if err != nil {
		return new(cdx.BOM), err
	}

	return bom, nil
}
