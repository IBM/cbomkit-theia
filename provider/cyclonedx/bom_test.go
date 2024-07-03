package cyclonedx

import (
	"testing"
)

var testfileFolder string = "./testfiles"

var tests = []struct {
	in  string
	err bool
}{
	{testfileFolder + "/algorithm.json", false},
	{testfileFolder + "/algorithmBroken.json", true},
	{testfileFolder + "/protocol.json", false},
}

var schemaPath string = "./bom-1.6.schema.json"

// Test if the BOMs are parsed as expected
func TestParseBOM(t *testing.T) {
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			_, err := ParseBOM(test.in, schemaPath)
			if (err != nil) != test.err {
				t.Fatalf("Failed to parse %v", test.in)
			}
		})
	}
}
