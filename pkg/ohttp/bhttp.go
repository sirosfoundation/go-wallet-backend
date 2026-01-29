// Package ohttp implements Binary HTTP (RFC 9292) encoding and decoding.
// This is used by OHTTP (RFC 9458) to encapsulate HTTP messages.
package ohttp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DecodeBinaryHTTPRequest parses a Binary HTTP request (RFC 9292).
// Returns an *http.Request that can be forwarded to the target server.
func DecodeBinaryHTTPRequest(data []byte) (*http.Request, error) {
	r := bytes.NewReader(data)

	// Framing indicator (known-length request = 0)
	framing, err := readVarint(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read framing: %w", err)
	}
	if framing != 0 {
		return nil, fmt.Errorf("unsupported framing indicator: %d (only known-length supported)", framing)
	}

	// Request control data: method, scheme, authority, path
	method, err := readLengthPrefixedString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read method: %w", err)
	}

	scheme, err := readLengthPrefixedString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read scheme: %w", err)
	}

	authority, err := readLengthPrefixedString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read authority: %w", err)
	}

	path, err := readLengthPrefixedString(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read path: %w", err)
	}

	// Build URL
	u := &url.URL{
		Scheme: scheme,
		Host:   authority,
	}

	// Parse path and query
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		u.Path = path[:idx]
		u.RawQuery = path[idx+1:]
	} else {
		u.Path = path
	}

	// Headers (known-length field section)
	headers, err := readFieldSection(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read headers: %w", err)
	}

	// Body (known-length content)
	body, err := readContent(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	// Trailers (known-length field section) - typically empty
	_, err = readFieldSection(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read trailers: %w", err)
	}

	// Build http.Request
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, u.String(), bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers (lowercase in Binary HTTP)
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Set content length if we have a body
	if len(body) > 0 {
		req.ContentLength = int64(len(body))
	}

	return req, nil
}

// EncodeBinaryHTTPResponse encodes an HTTP response as Binary HTTP.
func EncodeBinaryHTTPResponse(resp *http.Response) ([]byte, error) {
	var buf bytes.Buffer

	// Framing indicator (known-length response = 0)
	buf.Write(encodeVarint(0))

	// Response control data: status code
	buf.Write(encodeVarint(uint64(resp.StatusCode)))

	// Headers
	if err := writeFieldSection(&buf, resp.Header); err != nil {
		return nil, fmt.Errorf("failed to write headers: %w", err)
	}

	// Body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}
	if err := writeContent(&buf, body); err != nil {
		return nil, fmt.Errorf("failed to write body: %w", err)
	}

	// Empty trailers
	buf.Write(encodeVarint(0))

	return buf.Bytes(), nil
}

// EncodeBinaryHTTPRequest encodes an HTTP request as Binary HTTP.
// This is useful for testing (simulating the frontend).
func EncodeBinaryHTTPRequest(method, scheme, authority, path string, headers http.Header, body []byte) ([]byte, error) {
	var buf bytes.Buffer

	// Framing indicator (known-length request = 0)
	buf.Write(encodeVarint(0))

	// Request control data
	writeLengthPrefixedString(&buf, method)
	writeLengthPrefixedString(&buf, scheme)
	writeLengthPrefixedString(&buf, authority)
	writeLengthPrefixedString(&buf, path)

	// Headers
	if err := writeFieldSection(&buf, headers); err != nil {
		return nil, fmt.Errorf("failed to write headers: %w", err)
	}

	// Body
	if err := writeContent(&buf, body); err != nil {
		return nil, fmt.Errorf("failed to write body: %w", err)
	}

	// Empty trailers
	buf.Write(encodeVarint(0))

	return buf.Bytes(), nil
}

// Varint encoding (RFC 9292 / QUIC style)
// 1, 2, 4, or 8 bytes depending on value
func encodeVarint(v uint64) []byte {
	if v <= 63 {
		// 6-bit value, 1 byte: 00xxxxxx
		return []byte{byte(v)}
	}
	if v <= 16383 {
		// 14-bit value, 2 bytes: 01xxxxxx xxxxxxxx
		return []byte{
			byte(0x40 | (v >> 8)),
			byte(v),
		}
	}
	if v <= 1073741823 {
		// 30-bit value, 4 bytes: 10xxxxxx ...
		return []byte{
			byte(0x80 | (v >> 24)),
			byte(v >> 16),
			byte(v >> 8),
			byte(v),
		}
	}
	// 62-bit value, 8 bytes: 11xxxxxx ...
	return []byte{
		byte(0xC0 | (v >> 56)),
		byte(v >> 48),
		byte(v >> 40),
		byte(v >> 32),
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	}
}

func readVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}

	prefix := first[0] >> 6
	switch prefix {
	case 0:
		// 6-bit value
		return uint64(first[0] & 0x3F), nil
	case 1:
		// 14-bit value
		var second [1]byte
		if _, err := io.ReadFull(r, second[:]); err != nil {
			return 0, err
		}
		return uint64(first[0]&0x3F)<<8 | uint64(second[0]), nil
	case 2:
		// 30-bit value
		var rest [3]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return uint64(first[0]&0x3F)<<24 | uint64(rest[0])<<16 | uint64(rest[1])<<8 | uint64(rest[2]), nil
	case 3:
		// 62-bit value
		var rest [7]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return uint64(first[0]&0x3F)<<56 | uint64(rest[0])<<48 | uint64(rest[1])<<40 |
			uint64(rest[2])<<32 | uint64(rest[3])<<24 | uint64(rest[4])<<16 |
			uint64(rest[5])<<8 | uint64(rest[6]), nil
	}
	return 0, fmt.Errorf("invalid varint prefix")
}

func readLengthPrefixedString(r io.Reader) (string, error) {
	length, err := readVarint(r)
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeLengthPrefixedString(w io.Writer, s string) error {
	w.Write(encodeVarint(uint64(len(s))))
	if len(s) > 0 {
		w.Write([]byte(s))
	}
	return nil
}

func readFieldSection(r io.Reader) (http.Header, error) {
	sectionLen, err := readVarint(r)
	if err != nil {
		return nil, err
	}

	headers := make(http.Header)
	if sectionLen == 0 {
		return headers, nil
	}

	section := make([]byte, sectionLen)
	if _, err := io.ReadFull(r, section); err != nil {
		return nil, err
	}

	sr := bytes.NewReader(section)
	for sr.Len() > 0 {
		name, err := readLengthPrefixedString(sr)
		if err != nil {
			return nil, fmt.Errorf("failed to read header name: %w", err)
		}
		value, err := readLengthPrefixedString(sr)
		if err != nil {
			return nil, fmt.Errorf("failed to read header value: %w", err)
		}
		headers.Add(name, value)
	}

	return headers, nil
}

func writeFieldSection(w io.Writer, headers http.Header) error {
	var buf bytes.Buffer

	for name, values := range headers {
		// Convert to lowercase as per RFC 9292
		lowerName := strings.ToLower(name)
		for _, value := range values {
			// Write field line: name_len, name, value_len, value
			buf.Write(encodeVarint(uint64(len(lowerName))))
			buf.WriteString(lowerName)
			buf.Write(encodeVarint(uint64(len(value))))
			buf.WriteString(value)
		}
	}

	// Write section length, then content
	w.Write(encodeVarint(uint64(buf.Len())))
	w.Write(buf.Bytes())
	return nil
}

func readContent(r io.Reader) ([]byte, error) {
	length, err := readVarint(r)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func writeContent(w io.Writer, data []byte) error {
	w.Write(encodeVarint(uint64(len(data))))
	if len(data) > 0 {
		w.Write(data)
	}
	return nil
}
