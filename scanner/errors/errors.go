package errors

import (
	"errors"
	"fmt"
)

var ErrInsufficientInformation = errors.New("scanner: insufficient information to continue")

func GetInsufficientInformationError(msg string, plugin string, affectedObjectType string, affectedObjectName string) error {
	return fmt.Errorf("%w: (%v:%v:%v) %v", ErrInsufficientInformation, plugin, affectedObjectType, affectedObjectName, msg)
}

var ErrParsingFailedAlthoughChecked = errors.New("scanner: failed to parse file that was assumed to be a valid configuration")

func GetParsingFailedAlthoughCheckedError(parsingError error, plugin string) error {
	return fmt.Errorf("%w: (%v) %w", ErrInsufficientInformation, plugin, parsingError)
}