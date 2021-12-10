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

func TestIsValidWithConfig(t *testing.T) {
	testcases := []struct {
		name       string
		pattern    string
		length     int
		testString string
		want       bool
	}{
		{
			name:       "accept lowercase",
			pattern:    `^[a-z0-9][a-z0-9-]+[a-z0-9]$`,
			length:     64,
			testString: "somestring",
			want:       true,
		},
		{
			name:       "accept only 1 alphabet",
			pattern:    `[a-z]`,
			length:     64,
			testString: "a",
			want:       true,
		},
		{
			name:       "accept only 1 alphabet",
			pattern:    `[a-z]`,
			length:     64,
			testString: "1",
			want:       false,
		},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			s := sanitizer.NewSanitizerWithConfig(testcase.pattern, testcase.length)
			if got := s.IsValid(testcase.testString); got != testcase.want {
				t.Errorf("test: %s and want: %t, got %t", testcase.testString, testcase.want, got)
			}
		})
	}
}
