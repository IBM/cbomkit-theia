package main

import (
	"testing"
)

var testfileFolder string = "./testdata"
var filesystemExtension string = "/filesystem"
var outputExtension string = "/out"
var bomFolder string = "./provider/cyclonedx/testfiles"

var tests = []struct {
	in  string
	bom string
	err bool
}{
	{testfileFolder + "/1" + filesystemExtension, bomFolder + "/protocol.json", false},
}

var schemaPath string = "./bom-1.6.schema.json"

func TestParseBOM(t *testing.T) {
	for _, test := range tests {
		t.Run(test.in+", BOM: "+test.bom, func(t *testing.T) {
			output := run(&test.bom, &test.in)
			print(output)
			// TODO: Diff with output (something like https://github.com/josephburnett/jd)
		})
	}
}
