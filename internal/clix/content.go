package clix

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"strings"
)

// ParseContentValue extracts the bytes from a flag
func ParseContentValue(rawvalue string, defaultispath bool) []byte {
	if strings.HasPrefix(rawvalue, "base64:") {
		b, _ := base64.StdEncoding.DecodeString(rawvalue[7:])
		return b
	}
	if strings.HasPrefix(rawvalue, "raw-base64:") {
		b, _ := base64.RawStdEncoding.DecodeString(rawvalue[11:])
		return b
	}
	if strings.HasPrefix(rawvalue, "hex:") {
		b, _ := hex.DecodeString(rawvalue[4:])
		return b
	}
	if strings.HasPrefix(rawvalue, "file:") {
		b, _ := ioutil.ReadFile(rawvalue[5:])
		return b
	}
	if defaultispath {
		b, _ := ioutil.ReadFile(rawvalue)
		return b
	}
	return []byte(rawvalue)
}

// ContentUsage returns the ways to fill a content value
func ContentUsage() string {
	return `Formats:
	'raw value'
	'base64:BASE64CONTENT'
	'hex:HEXCONTENT'
	'file:/path/to/file'`
}
