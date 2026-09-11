package main

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DecodeCandidate is one decoding attempt result.
type DecodeCandidate struct {
	Text   string
	Method string
}

const (
	minEncodedLen        = 12
	defaultMaxCandidates = 6
)

var (
	base64StrictRe  = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	unicodeEscapeRe = regexp.MustCompile(`\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}`)
	hexStrictRe     = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// rot13 decodes ROT13 (self-inverse).
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 97 && c <= 122:
			b[i] = 97 + (c-97+13)%26
		case c >= 65 && c <= 90:
			b[i] = 65 + (c-65+13)%26
		}
	}
	return string(b)
}

// isPrintableText rejects binary garbage to suppress false positives.
func isPrintableText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	runes := []rune(s)
	ok := 0
	for _, r := range runes {
		if r == 10 || r == 9 || r == 13 {
			ok++
			continue
		}
		if r >= 0x20 && r != 0x7f {
			ok++
		}
	}
	return float64(ok)/float64(len(runes)) > 0.9
}

// decodeBase64 decodes only strictly valid, printable base64 payloads.
func decodeBase64(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < minEncodedLen || len(t)%4 != 0 {
		return "", false
	}
	if !base64StrictRe.MatchString(t) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(t)
	if err != nil {
		return "", false
	}
	out := string(raw)
	if !isPrintableText(out) {
		return "", false
	}
	return out, true
}

// decodeUnicodeEscape decodes \uXXXX and \xXX sequences.
func decodeUnicodeEscape(s string) (string, bool) {
	if !unicodeEscapeRe.MatchString(s) {
		return "", false
	}
	out := unicodeEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
		code, err := strconv.ParseInt(m[2:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(code))
	})
	if out == s || !isPrintableText(out) {
		return "", false
	}
	return out, true
}

// decodeURLPercent decodes percent-encoding.
func decodeURLPercent(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return "", false
	}
	out, err := url.QueryUnescape(s)
	if err != nil || out == s {
		return "", false
	}
	if !isPrintableText(out) {
		return "", false
	}
	return out, true
}

// decodeHex decodes hex strings such as 48656c6c6f.
func decodeHex(s string) (string, bool) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(t, "0x")
	if len(t) < minEncodedLen || len(t)%2 != 0 {
		return "", false
	}
	if !hexStrictRe.MatchString(t) {
		return "", false
	}
	raw := make([]byte, 0, len(t)/2)
	for i := 0; i < len(t); i += 2 {
		v, err := strconv.ParseUint(t[i:i+2], 16, 8)
		if err != nil {
			return "", false
		}
		raw = append(raw, byte(v))
	}
	out := string(raw)
	if !isPrintableText(out) {
		return "", false
	}
	return out, true
}

// stripSeparators removes whitespace and separators used to split keywords
// (e.g. "忽 略 指 令"), countering word-splitting evasion.
func stripSeparators(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		switch r {
		case '-', '_', '.', '*', '+', '~', '`', '\'', '"', '|', '/', '\\':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NormalizeForDetection builds detection candidates.
// The original text is always the first candidate; decoded variants follow.
func NormalizeForDetection(raw string, maxCandidates int) []DecodeCandidate {
	if maxCandidates <= 0 {
		maxCandidates = defaultMaxCandidates
	}
	cands := []DecodeCandidate{{Text: raw, Method: "original"}}
	seen := map[string]bool{raw: true}

	add := func(text, method string) {
		if len(cands) >= maxCandidates || text == "" || seen[text] {
			return
		}
		seen[text] = true
		cands = append(cands, DecodeCandidate{Text: text, Method: method})
	}

	if out, ok := decodeBase64(raw); ok {
		add(out, "base64")
	}
	if out, ok := decodeUnicodeEscape(raw); ok {
		add(out, "unicode_escape")
	}
	if out, ok := decodeURLPercent(raw); ok {
		add(out, "url_percent")
	}
	if out, ok := decodeHex(raw); ok {
		add(out, "hex")
	}
	add(rot13(raw), "rot13")
	add(stripSeparators(raw), "strip_separators")

	return cands
}
