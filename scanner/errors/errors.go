package errors

import (
	"errors"
	"fmt"
)

// Error to represent cases in which a plugin had to interrupt its execution due to missing information (e.g. in the BOM or in the filesystem)
var ErrInsufficientInformation = errors.New("scanner: insufficient information to continue")

func GetInsufficientInformationError(msg string, plugin string, affectedObjectType string, affectedObjectName string) error {
	return fmt.Errorf("%w: (%v:%v:%v) %v", ErrInsufficientInformation, plugin, affectedObjectType, affectedObjectName, msg)
}

// Error to represent cases in which parsing of a relevant file failed although the plugin verified the file beforehand; this error might suggest an bug
var ErrParsingFailedAlthoughChecked = errors.New("scanner: failed to parse file that was assumed to be a valid configuration")

func GetParsingFailedAlthoughCheckedError(parsingError error, plugin string) error {
	return fmt.Errorf("%w: (%v) %w", ErrParsingFailedAlthoughChecked, plugin, parsingError)
}
