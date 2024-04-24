package cyclonedx

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/xeipuuv/gojsonschema"
	"google.golang.org/protobuf/encoding/protojson"
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

	var bom map[string]interface{}

	if err := json.Unmarshal(dat, &bom); err != nil {
		panic(err)
	}

	protoBom := &Bom{}

	log.Default().Println(bom)

	options := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}

	if err = options.Unmarshal(dat, protoBom); err != nil {
		panic(err)
	}

	log.Default().Printf("%+v", protoBom)

}
