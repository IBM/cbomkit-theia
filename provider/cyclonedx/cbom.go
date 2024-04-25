package cyclonedx

import (
	"bytes"
	"fmt"
	"log"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/xeipuuv/gojsonschema"
)

func Check(e error) {
	if e != nil {
		panic(e)
	}
}

func WriteCBOM(bom *cdx.BOM, file *os.File) {
	// Encode the BOM
	err := cdx.NewBOMEncoder(file, cdx.BOMFileFormatJSON).
		SetPretty(true).
		Encode(bom)
	Check(err)
}

func ParseBOM(path string) *cdx.BOM {
	// Read BOM
	dat, err := os.ReadFile(path)
	Check(err)
	log.Default().Println("Read BOM file successfully")

	// JSON Validation via Schema
	schemaLoader := gojsonschema.NewReferenceLoader("file://./provider/cyclonedx/bom-1.6.schema.json")
	documentLoader := gojsonschema.NewStringLoader(string(dat))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	Check(err)

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
	Check(err)
	log.Default().Println("Successfully decoded BOM")

	return bom
}
