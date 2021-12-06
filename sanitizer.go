package sanitizer

import "regexp"

type Sanitizer interface {
	IsValid(string) bool
}

type sanitizer struct {
	acceptablePattern *regexp.Regexp
	maxLength         int
}

func NewSanitizer() Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]+[a-z0-9]$`),
		maxLength:         63,
	}
}

func NewSanitizerWithConfig(pattern string, length int) Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(pattern),
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
