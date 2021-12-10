package sanitizer

import "regexp"

type Sanitizer interface {
	IsValid(string) bool
}

type sanitizer struct {
	acceptablePattern *regexp.Regexp
	validationPattern *regexp.Regexp
	separator         string
	maxLength         int
}

func NewSubdomainLabelSafe() Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]+[a-z0-9]$`),
		validationPattern: regexp.MustCompile(`[a-z0-9]*`),
		separator:         "-",
		maxLength:         63,
	}
}

func NewSanitizerWithConfig(pattern, validation, separator string, length int) Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(pattern),
		validationPattern: regexp.MustCompile(validation),
		separator:         separator,
		maxLength:         length,
	}
}

func (s *sanitizer) IsValid(str string) bool {
	if !s.acceptablePattern.MatchString(str) {
		return false
	}
	if s.maxLength < len(str) {
		return false
	}

	return true
}
