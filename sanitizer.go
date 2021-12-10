package sanitizer

import (
	"fmt"
	"hash/fnv"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
)

type Sanitizer interface {
	IsValid(string) bool
	Sanitize(string) (string, error)
}

// sanitizer will check given string by acceptablePattern.
// or generate valid string by validationPattern and acceptablePattern.
type sanitizer struct {
	acceptablePattern *regexp.Regexp
	validationPattern *regexp.Regexp
	separator         string
	maxLength         int
}

// NewSubdomainLabelSafe is a preset for sanitizing a subdomain safe string.
func NewSubdomainLabelSafe() Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(`^[a-z0-9][a-z0-9-]+[a-z0-9]$`),
		validationPattern: regexp.MustCompile(`[a-z0-9]+`),
		separator:         "-",
		maxLength:         63,
	}
}

// NewSanitizerWithConfig can be used to set the config values.
func NewSanitizerWithConfig(pattern, validation, separator string, length int) Sanitizer {
	return &sanitizer{
		acceptablePattern: regexp.MustCompile(pattern),
		validationPattern: regexp.MustCompile(validation),
		separator:         separator,
		maxLength:         length,
	}
}

// IsValid returns a boolean value which indicates given string is valid by acceptablePattern or not.
func (s *sanitizer) IsValid(str string) bool {
	if !s.acceptablePattern.MatchString(str) {
		return false
	}
	if s.maxLength < len(str) {
		return false
	}

	return true
}

// Sanitize returns a `valid` string.
// If the given string is valid, return it.
// Otherwise, it will try to concatenate the strings matching the validationPattern with the separator to make a valid string.
func (s *sanitizer) Sanitize(token string) (string, error) {
	if s.IsValid(token) {
		return token, nil
	}
	matches := s.validationPattern.FindAllStringSubmatch(token, -1)
	var validatedTokens []string
	for _, w := range matches {
		validatedTokens = append(validatedTokens, w[0])
	}

	// if validatedName is short enough, return it
	validatedName := strings.Join(validatedTokens, s.separator)
	if len(validatedName) < s.maxLength {
		return validatedName, nil
	}

	validatedNameWithHash, err := s.addHash(token, validatedName)
	if err != nil {
		return "", errors.Wrap(err, "failed to add Hash")
	}
	return validatedNameWithHash, nil
}

// addHash returns string which is like `str-hash(raw)`
// addHash requires raw string due to prevent duplication
func (s *sanitizer) addHash(raw, str string) (string, error) {
	// currently, use fnv.New32a() and it returns as 8 characters
	hashLen := 8
	// support when the maxLength is too short
	if s.maxLength < hashLen {
		hashLen = s.maxLength / 2
	}

	hash, err := getHash(raw)
	if err != nil {
		return "", errors.Wrap(err, "failed to get hash")
	}

	return fmt.Sprintf("%s%s%s", str[:(s.maxLength-hashLen-1)], s.separator, hash[:hashLen]), nil
}

func getHash(str string) (string, error) {
	h := fnv.New32a()
	if _, err := io.WriteString(h, str); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
