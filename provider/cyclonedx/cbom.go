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

func ParseCBOM(path string) {
	dat, err := os.ReadFile(path)

	Check(err)

	// JSON Validation via Schema
	schemaLoader := gojsonschema.NewReferenceLoader("file://./provider/cyclonedx/bom-1.6.schema.json")
	documentLoader := gojsonschema.NewStringLoader(string(dat))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	Check(err)

	if result.Valid() {
		log.Default().Printf("Provided BOM is valid.\n")
	} else {
		log.Default().Println("The document is not valid. see errors :")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
	}

	test_bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(dat), cdx.BOMFileFormatJSON)

	if err = decoder.Decode(test_bom); err != nil {
		panic(err)
	}

	log.Default().Printf("Successfully decoded BOM")

}
