package sanitizer

import (
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strings"
)

type Sanitizer interface {
	IsValid(string) bool
	SanitizeString(string) (string, error)
	SanitizeStrings(...string) (string, error)
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

func (s *sanitizer) SanitizeString(token string) (string, error) {
	if s.IsValid(token) {
		return token, nil
	}

	validWords := s.validationPattern.FindAllStringSubmatch(token, -1)
	var validatedNames []string
	for _, w := range validWords {
		validatedNames = append(validatedNames, w[0])
	}

	validatedName := strings.Join(validatedNames, s.separator)

	if s.maxLength < len(validatedName) {
		validatedName = validatedName[:s.maxLength]
	}
	return validatedName, nil
}

func (s *sanitizer) SanitizeStrings(tokens ...string) (string, error) {
	token := strings.Join(tokens, s.separator)
	if s.IsValid(token) {
		return token, nil
	}
	return token, nil
}

func GetHash(str string) (string, error) {
	h := fnv.New32a()
	if _, err := io.WriteString(h, str); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
