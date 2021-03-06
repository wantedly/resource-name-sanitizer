package sanitizer_test

import (
	"testing"

	"github.com/wantedly/resource-name-sanitizer"
)

func TestIsValidSubdomainLabelSafe(t *testing.T) {
	testcases := []struct {
		name       string
		testString string
		want       bool
	}{
		{
			name:       "accept lowercase",
			testString: "somestring",
			want:       true,
		},
		{
			name:       "doesn't accept uppercase",
			testString: "someString",
			want:       false,
		},
		{
			name:       "accept lowercase and dash",
			testString: "some-string",
			want:       true,
		},
		{
			name:       "doesn't accept long string",
			testString: "some-long-64-characters-string-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want:       false,
		},
		{
			name:       "doesn't accept special character like slash",
			testString: "some/string",
			want:       false,
		},
	}

	s := sanitizer.NewSubdomainLabelSafe()
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			if got := s.IsValid(testcase.testString); got != testcase.want {
				t.Errorf("test: %s and want: %t, got %t", testcase.testString, testcase.want, got)
			}
		})
	}
}

func TestSanitize_SubdomainLabelSafe(t *testing.T) {
	testcases := []struct {
		name string
		test string
		want string
	}{
		{
			name: "return same string when it gets acceptable string",
			test: "somestring",
			want: "somestring",
		},
		{
			name: "accept dash between characters",
			test: "some-string",
			want: "some-string",
		},
		{
			name: "trim latest special character",
			test: "some-string%",
			want: "some-string-71ea0770",
		},
		{
			name: "replace special characters",
			test: "some/string%included*special&characters",
			want: "some-string-included-special-characters-0c185f7f",
		},
		{
			name: "long string will be trimmed",
			test: "some-long-characters-string-abcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefg",
			want: "some-long-characters-string-abcdefgabcdefgabcdefgabcde-5c75d198",
		},
		{
			name: "long string has special characters will be trimmed and replaced",
			test: "some%long/characters*string$abcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefg",
			want: "some-long-characters-string-abcdefgabcdefgabcdefgabcde-b43b67da",
		},
		{
			name: "long string has special characters",
			test: "some%long-characters*string-abcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefgabcdefg",
			want: "some-long-characters-string-abcdefgabcdefgabcdefgabcde-537aa79b",
		},
		{
			name: "can be join and sanitize special case",
			test: "some/string%-included*special-&characters",
			want: "some-string-included-special-characters-8622b7b7",
		},
	}

	s := sanitizer.NewSubdomainLabelSafe()
	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			got := s.Sanitize(testcase.test)
			if testcase.want != got {
				t.Errorf("test: %s and want: %s, got: %s", testcase.test, testcase.want, got)
			}
			if !s.IsValid(got) {
				t.Errorf("got: %s is not valid", got)
			}
		})
	}
}

func TestIsValidWithConfig(t *testing.T) {
	testcases := []struct {
		name       string
		pattern    string
		validator  string
		separator  string
		length     int
		testString string
		want       bool
	}{
		{
			name:       "accept lowercase",
			pattern:    `^[a-z0-9][a-z0-9-]+[a-z0-9]$`,
			validator:  `[a-z0-9]`,
			separator:  "-",
			length:     64,
			testString: "somestring",
			want:       true,
		},
		{
			name:       "accept only 1 alphabet",
			pattern:    `[a-z]`,
			validator:  `[a-z]`,
			separator:  "",
			length:     64,
			testString: "a",
			want:       true,
		},
		{
			name:       "accept only 1 alphabet",
			pattern:    `[a-z]`,
			validator:  `[a-z]`,
			separator:  "",
			length:     64,
			testString: "1",
			want:       false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			s := sanitizer.NewSanitizerWithConfig(testcase.pattern, testcase.validator, testcase.separator, testcase.length)
			if got := s.IsValid(testcase.testString); got != testcase.want {
				t.Errorf("test: %s and want: %t, got %t", testcase.testString, testcase.want, got)
			}
		})
	}
}
