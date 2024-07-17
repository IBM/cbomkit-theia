package confidencelevel

import (
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Represents a confidence level; a new ConfidenceLevel has maximum confidence
type ConfidenceLevel struct {
	count int
	sum   int
	value int
}

// Modifiers for the ConfidenceLevel
type ConfidenceLevelModifier int

const (
	confidenceLevelMax                                             = 100
	confidenceLevelMin                                             = 0
	ConfidenceLevelModifierPositiveExtreme ConfidenceLevelModifier = 50
	ConfidenceLevelModifierPositiveHigh    ConfidenceLevelModifier = 30
	ConfidenceLevelModifierPositiveMedium  ConfidenceLevelModifier = 15
	ConfidenceLevelModifierPositiveLow     ConfidenceLevelModifier = 5
	ConfidenceLevelModifierNegativeExtreme ConfidenceLevelModifier = -50
	ConfidenceLevelModifierNegativeHigh    ConfidenceLevelModifier = -30
	ConfidenceLevelModifierNegativeMedium  ConfidenceLevelModifier = -15
	ConfidenceLevelModifierNegativeLow     ConfidenceLevelModifier = -5
)

// Get a new ConfidenceLevel; default value is confidenceLevelMax (full confidence)
func New() *ConfidenceLevel {
	return &ConfidenceLevel{
		count: 0,
		sum:   0,
		value: confidenceLevelMax,
	}
}

// Get the value of the ConfidenceLevel
func (confidenceLevel *ConfidenceLevel) GetValue() int {
	return confidenceLevel.value
}

// Generate a CycloneDX component property from this confidence
func (confidenceLevel *ConfidenceLevel) GetProperty() cdx.Property {
	return cdx.Property{
		Name:  "cics_confidence_level",
		Value: fmt.Sprint(confidenceLevel.value),
	}
}

// Modify the confidence level using one of the predefined ConfidenceLevelModifier values
func (confidenceLevel *ConfidenceLevel) Modify(modifier ConfidenceLevelModifier) {
	confidenceLevel.value += int(modifier)

	if confidenceLevel.value < confidenceLevelMin {
		confidenceLevel.value = confidenceLevelMin
	} else if confidenceLevel.value > confidenceLevelMax {
		confidenceLevel.value = confidenceLevelMax
	}
}

/*
	Sets the value of this ConfidenceLevel to the average of all sub ConfidenceLevels; set ignoreMaxConfidence to ignore sub ConfidenceLevels with value confidenceLevelMax

Example:

a, b, c := New(), New(),  New()

a.AddSubConfidenceLevel(b, false)

a.AddSubConfidenceLevel(c, false)

Now a.GetValue() returns the average of b.GetValue() and c.GetValue(). (a.value = (b.value+c.value)/2)

Warning: a, b and c are not permanently linked by this. AddSubConfidenceLevel just calculates the average in this moment
*/
func (confidenceLevel *ConfidenceLevel) AddSubConfidenceLevel(sub ConfidenceLevel, ignoreMaxConfidence bool) {
	if ignoreMaxConfidence && sub.value == confidenceLevelMax {
		return
	}
	confidenceLevel.count++
	confidenceLevel.sum += sub.value
	confidenceLevel.value = confidenceLevel.sum / confidenceLevel.count
}
