# resource-name-sanitizer

resource-name-sanitizer sanitize the given string with an appropriate pattern

## Overview
The resource-name-sanitizer can be used to check if a string matches a certain pattern.
You can also sanitize a string by registering a validation pattern

`NewSubdomainLabelSafe` is provided as a preset. You can also set your own configuration by `NewSanitizerWithConfig`

## Installing
```
go get -u github.com/wantedly/resource-name-sanitizer
```
