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

func New() ConfidenceLevel {
	return ConfidenceLevel{
		count: 0,
		sum:   0,
		value: confidenceLevelMax,
	}
}

func (confidenceLevel *ConfidenceLevel) GetValue() int {
	return confidenceLevel.value
}

func (confidenceLevel *ConfidenceLevel) GetProp() cdx.Property {
	return cdx.Property{
		Name:  "cics_confidence_level",
		Value: fmt.Sprint(confidenceLevel.value),
	}
}

func (confidenceLevel *ConfidenceLevel) Modify(modifier ConfidenceLevelModifier) {
	confidenceLevel.value += int(modifier)

	if confidenceLevel.value < confidenceLevelMin {
		confidenceLevel.value = confidenceLevelMin
	} else if confidenceLevel.value > confidenceLevelMax {
		confidenceLevel.value = confidenceLevelMax
	}
}

func (confidenceLevel *ConfidenceLevel) AddSubConfidenceLevel(sub ConfidenceLevel, ignoreMaxConfidence bool) {
	if ignoreMaxConfidence && sub.value == confidenceLevelMax {
		return
	}
	confidenceLevel.count++
	confidenceLevel.sum += sub.value
	confidenceLevel.value = confidenceLevel.sum / confidenceLevel.count
}
