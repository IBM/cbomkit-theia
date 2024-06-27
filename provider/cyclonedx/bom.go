package cyclonedx

import (
	"bytes"
	"fmt"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/exp/slog"
)

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
