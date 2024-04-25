package cyclonedx

import (
	"bytes"
	"fmt"
	"log"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
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
	dat, err := os.ReadFile(path)
	if err != nil {
		return new(cdx.BOM), err
	}

	log.Default().Println("Read BOM file successfully")

	// JSON Validation via Schema
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + schemaPath)
	documentLoader := gojsonschema.NewStringLoader(string(dat))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return new(cdx.BOM), err
	}

	if result.Valid() {
		log.Default().Println("Provided BOM is valid.")
	} else {
		log.Default().Println("The BOM is not valid. see errors:")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
	}

	// Decode BOM from JSON
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(dat), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	if err != nil {
		return new(cdx.BOM), err
	}
	log.Default().Println("Successfully decoded BOM")

	return bom, nil
}
