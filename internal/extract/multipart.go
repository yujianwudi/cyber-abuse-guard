package extract

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"unicode/utf8"
)

const multipartDiscardBufferBytes = 32 << 10

func extractMultipart(body []byte, boundary string, limits Limits) Result {
	result := newRequestResult(body, limits)
	if reason := preflightMultipart(body, boundary, limits); reason != "" {
		result.addIncomplete(reason)
		result.finish()
		return result
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	discardBuffer := make([]byte, multipartDiscardBufferBytes)
	jsonExtractor := extractor{limits: limits, result: &result, requestMode: true}
	partCount := 0
	textFieldCount := 0
	multipartTextBytes := 0

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.addIncomplete(IncompleteMultipartParseError)
			break
		}
		partCount++
		if partCount > limits.MaxMultipartParts {
			result.addIncomplete(IncompleteMultipartPartLimit)
			_ = part.Close()
			break
		}
		if !multipartHeadersWithinLimits(part.Header, limits) {
			result.addIncomplete(IncompleteMultipartHeaderLimit)
			_ = part.Close()
			break
		}

		disposition, params, ok := parsePartDisposition(part.Header)
		if !ok {
			result.addIncomplete(IncompleteMultipartParseError)
			_ = part.Close()
			break
		}
		name, hasName := params["name"]
		_, hasFilename := params["filename"]
		if !hasName && disposition != "attachment" {
			result.addIncomplete(IncompleteMultipartParseError)
			_ = part.Close()
			break
		}

		partMediaType, mediaTypeOK := parsePartMediaType(part.Header)
		if !mediaTypeOK {
			result.addIncomplete(IncompleteMultipartParseError)
			_ = part.Close()
			break
		}
		if isMultipartFilePart(name, disposition, hasFilename, partMediaType) {
			result.OpaqueMedia = true
			markMultipartOpaque(&result, name, partMediaType)
			if _, err := io.CopyBuffer(io.Discard, part, discardBuffer); err != nil {
				result.addIncomplete(IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}
		if isMultipartMetadataField(name) {
			if _, err := io.CopyBuffer(io.Discard, part, discardBuffer); err != nil {
				result.addIncomplete(IncompleteMultipartParseError)
				_ = part.Close()
				break
			}
			_ = part.Close()
			continue
		}

		textFieldCount++
		if textFieldCount > limits.MaxMultipartTextFields {
			result.addIncomplete(IncompleteMultipartTextLimit)
			_ = part.Close()
			break
		}
		remainingMultipart := limits.MaxMultipartTextBytes - multipartTextBytes
		remainingScan := limits.MaxScanBytes - result.TextBytesScanned
		fieldLimit := minInt(limits.MaxMultipartTextPartBytes, remainingMultipart)
		fieldLimit = minInt(fieldLimit, remainingScan)
		if fieldLimit <= 0 {
			result.addIncomplete(IncompleteMultipartTextLimit)
			_ = part.Close()
			break
		}
		value, overflow, readOK := readMultipartText(part, fieldLimit)
		_ = part.Close()
		if !readOK {
			result.addIncomplete(IncompleteMultipartParseError)
			break
		}
		if overflow {
			result.addIncomplete(IncompleteMultipartTextLimit)
			break
		}
		if !utf8.Valid(value) || containsBinaryControl(string(value)) {
			result.addIncomplete(IncompleteMultipartParseError)
			break
		}
		multipartTextBytes += len(value)
		if isMultipartJSONField(name) && obviousJSON(value) {
			if err := jsonExtractor.walkJSON(value, contextText, 0, false); err != nil {
				result.addIncomplete(IncompleteMultipartParseError)
				break
			}
			if jsonExtractor.stop {
				break
			}
			continue
		}
		if !appendMultipartText(&result, string(value), limits, &multipartTextBytes) {
			break
		}
	}

	result.BytesScanned = result.TextBytesScanned
	result.finish()
	return result
}

// preflightMultipart enforces configured part-header and part-count bounds on
// the raw body before mime/multipart allocates MIMEHeader values. It is a
// conservative framing pass only; the standard library remains authoritative
// for syntax and boundary validation. The independent MaxRawBytes check runs
// before this function, so even malformed framing has a fixed scan bound.
func preflightMultipart(body []byte, boundary string, limits Limits) IncompleteReason {
	marker := []byte("--" + boundary)
	position := findMultipartBoundary(body, 0, marker)
	if position < 0 {
		return ""
	}
	partCount := 0
	for position >= 0 {
		afterMarker := position + len(marker)
		if afterMarker > len(body) {
			return ""
		}
		if bytes.HasPrefix(body[afterMarker:], []byte("--")) {
			return ""
		}
		lineEndingBytes := 0
		switch {
		case bytes.HasPrefix(body[afterMarker:], []byte("\r\n")):
			lineEndingBytes = 2
		case bytes.HasPrefix(body[afterMarker:], []byte("\n")):
			// mime/multipart deliberately accepts LF-only framing. Enforce the
			// same pre-allocation header bounds for that compatibility path.
			lineEndingBytes = 1
		default:
			return ""
		}
		partCount++
		if partCount > limits.MaxMultipartParts {
			return IncompleteMultipartPartLimit
		}

		headerStart := afterMarker + lineEndingBytes
		searchEnd := headerStart + limits.MaxMultipartHeaderBytes + len("\r\n\r\n")
		if searchEnd > len(body) {
			searchEnd = len(body)
		}
		relativeEnd, separatorBytes := multipartHeaderTerminator(body[headerStart:searchEnd])
		if relativeEnd < 0 {
			if len(body)-headerStart > limits.MaxMultipartHeaderBytes {
				return IncompleteMultipartHeaderLimit
			}
			return ""
		}
		headerEnd := headerStart + relativeEnd
		headerBlock := body[headerStart:headerEnd]
		if len(headerBlock) > limits.MaxMultipartHeaderBytes || rawMultipartHeaderCount(headerBlock) > limits.MaxMultipartHeaders {
			return IncompleteMultipartHeaderLimit
		}

		contentStart := headerEnd + separatorBytes
		position = findMultipartBoundary(body, contentStart, marker)
	}
	return ""
}

func findMultipartBoundary(body []byte, start int, marker []byte) int {
	if start < 0 {
		start = 0
	}
	for start <= len(body)-len(marker) {
		relative := bytes.Index(body[start:], marker)
		if relative < 0 {
			return -1
		}
		position := start + relative
		preceded := position == 0 || position > 0 && body[position-1] == '\n'
		after := position + len(marker)
		terminated := bytes.HasPrefix(body[after:], []byte("\r\n")) ||
			bytes.HasPrefix(body[after:], []byte("\n")) ||
			bytes.HasPrefix(body[after:], []byte("--"))
		if preceded && terminated {
			return position
		}
		start = position + 1
	}
	return -1
}

func multipartHeaderTerminator(block []byte) (index, separatorBytes int) {
	crlf := bytes.Index(block, []byte("\r\n\r\n"))
	lf := bytes.Index(block, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf <= lf):
		return crlf, 4
	case lf >= 0:
		return lf, 2
	default:
		return -1, 0
	}
}

func rawMultipartHeaderCount(headerBlock []byte) int {
	if len(headerBlock) == 0 {
		return 0
	}
	count := 0
	for _, line := range bytes.Split(headerBlock, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			count++
		}
	}
	return count
}

func multipartHeadersWithinLimits(header textproto.MIMEHeader, limits Limits) bool {
	headerCount := 0
	headerBytes := 0
	for key, values := range header {
		headerCount += len(values)
		headerBytes += len(key)
		for _, value := range values {
			headerBytes += len(value)
		}
		if headerCount > limits.MaxMultipartHeaders || headerBytes > limits.MaxMultipartHeaderBytes {
			return false
		}
	}
	return true
}

func parsePartDisposition(header textproto.MIMEHeader) (string, map[string]string, bool) {
	values := mimeHeaderValues(header, "Content-Disposition")
	if len(values) != 1 {
		return "", nil, false
	}
	disposition, params, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", nil, false
	}
	disposition = strings.ToLower(strings.TrimSpace(disposition))
	if disposition != "form-data" && disposition != "attachment" {
		return "", nil, false
	}
	return disposition, params, true
}

func parsePartMediaType(header textproto.MIMEHeader) (string, bool) {
	values := mimeHeaderValues(header, "Content-Type")
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 {
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(values[0])
	if err != nil {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(mediaType)), true
}

func mimeHeaderValues(header textproto.MIMEHeader, name string) []string {
	var result []string
	for key, values := range header {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			result = append(result, values...)
		}
	}
	return result
}

func isMultipartFilePart(name, disposition string, hasFilename bool, mediaType string) bool {
	if disposition == "attachment" || hasFilename || isMultipartFileField(name) {
		return true
	}
	switch {
	case strings.HasPrefix(mediaType, "image/"),
		strings.HasPrefix(mediaType, "audio/"),
		strings.HasPrefix(mediaType, "video/"),
		strings.HasPrefix(mediaType, "multipart/"),
		mediaType == "application/octet-stream",
		mediaType == "application/pdf",
		mediaType == "application/msword",
		strings.HasPrefix(mediaType, "application/vnd.openxmlformats-officedocument"):
		return true
	}
	return mediaType != "" && !strings.HasPrefix(mediaType, "text/") && !isJSONMediaType(mediaType)
}

func isMultipartFileField(name string) bool {
	canonical := canonicalMultipartField(name)
	switch canonical {
	case "image", "images", "mask", "file", "files", "audio", "video", "document", "attachment":
		return true
	default:
		return false
	}
}

func isMultipartMetadataField(name string) bool {
	canonical := canonicalMultipartField(name)
	switch canonical {
	case "model", "size", "quality", "n", "responseformat", "style", "user", "stream", "seed", "format", "outputformat":
		return true
	default:
		return false
	}
}

func isMultipartJSONField(name string) bool {
	switch canonicalMultipartField(name) {
	case "messages", "message", "input", "instructions", "system", "contents", "parts":
		return true
	default:
		return false
	}
}

func canonicalMultipartField(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "[]")
	return canonicalKey(name)
}

func markMultipartOpaque(result *Result, name, mediaType string) {
	kind := mediaContextForMIME(mediaType)
	if kind == mediaContextNone {
		switch canonicalMultipartField(name) {
		case "image", "images", "mask":
			kind = mediaContextImage
		case "audio":
			kind = mediaContextAudio
		case "video":
			kind = mediaContextVideo
		case "file", "files", "document", "attachment":
			kind = mediaContextDocument
		default:
			kind = mediaContextOther
		}
	}
	x := extractor{result: result}
	x.markOpaqueMedia(directOpaqueKind(kind))
}

func readMultipartText(part *multipart.Part, limit int) ([]byte, bool, bool) {
	reader := &io.LimitedReader{R: part, N: int64(limit) + 1}
	value, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, false
	}
	if len(value) <= limit {
		return value, false, true
	}
	return value[:limit], true, true
}

func appendMultipartText(result *Result, value string, limits Limits, multipartTextBytes *int) bool {
	if strings.TrimSpace(value) == "" {
		return true
	}
	if len(result.Parts) >= limits.MaxTextParts {
		result.addIncomplete(IncompleteTextPartLimit)
		return false
	}
	result.Parts = append(result.Parts, value)
	result.TextBytesScanned += len(value)

	decoded, encoded, incomplete := decodeBoundedText(value)
	if encoded && incomplete {
		result.addIncomplete(IncompleteMultipartTextLimit)
		return false
	}
	for _, variant := range decoded {
		if strings.TrimSpace(variant) == "" {
			continue
		}
		remainingMultipart := limits.MaxMultipartTextBytes - *multipartTextBytes
		remainingScan := limits.MaxScanBytes - result.TextBytesScanned
		allowed := minInt(len(variant), minInt(remainingMultipart, remainingScan))
		if allowed < len(variant) {
			result.addIncomplete(IncompleteMultipartTextLimit)
			return false
		}
		if len(result.Parts) >= limits.MaxTextParts {
			result.addIncomplete(IncompleteTextPartLimit)
			return false
		}
		result.Parts = append(result.Parts, variant)
		result.TextBytesScanned += len(variant)
		*multipartTextBytes += len(variant)
	}
	return true
}
