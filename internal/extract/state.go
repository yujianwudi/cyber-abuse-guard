package extract

// Completeness separates a fully inspected request from content whose local
// inspection could not be completed. Opaque media alone does not make a
// request incomplete.
type Completeness string

const (
	CompletenessComplete   Completeness = "complete"
	CompletenessIncomplete Completeness = "incomplete_inspection"

	// Short aliases keep call sites readable while the explicit names avoid
	// ambiguity in exported structs.
	Complete             = CompletenessComplete
	IncompleteInspection = CompletenessIncomplete
)

// IncompleteReason is a content-free enum suitable for counters and audit
// metadata. Values must never contain parser errors or request-derived data.
type IncompleteReason string

const (
	IncompleteParseError                     IncompleteReason = "parse_error"
	IncompleteScanByteLimit                  IncompleteReason = "scan_byte_limit"
	IncompleteJSONDepthLimit                 IncompleteReason = "json_depth_limit"
	IncompleteJSONTokenLimit                 IncompleteReason = "json_token_limit"
	IncompleteJSONNodeLimit                  IncompleteReason = "json_node_limit"
	IncompleteTextPartLimit                  IncompleteReason = "text_part_limit"
	IncompleteTextPartByteLimit              IncompleteReason = "text_part_byte_limit"
	IncompleteMultipartBoundaryLimit         IncompleteReason = "multipart_boundary_limit"
	IncompleteMultipartPartLimit             IncompleteReason = "multipart_part_limit"
	IncompleteMultipartHeaderLimit           IncompleteReason = "multipart_header_limit"
	IncompleteMultipartTextLimit             IncompleteReason = "multipart_text_limit"
	IncompleteMultipartParseError            IncompleteReason = "multipart_parse_error"
	IncompleteMultipartUnknownField          IncompleteReason = "multipart_unknown_field"
	IncompleteMultipartTextFieldTypeMismatch IncompleteReason = "multipart_text_field_type_mismatch"
	IncompleteToolSchema                     IncompleteReason = "tool_schema"
	IncompleteDeferredTextCandidateLimit     IncompleteReason = "deferred_text_candidate_limit"
	IncompleteUnsupportedMediaType           IncompleteReason = "unsupported_media_type"
	IncompleteUnsupportedContentEncoding     IncompleteReason = "unsupported_content_encoding"
	IncompleteRawBodyLimit                   IncompleteReason = "raw_body_limit"
	IncompleteRPCBodyLimit                   IncompleteReason = "rpc_body_limit"
)

var incompleteReasonOrder = [...]IncompleteReason{
	IncompleteParseError,
	IncompleteScanByteLimit,
	IncompleteJSONDepthLimit,
	IncompleteJSONTokenLimit,
	IncompleteJSONNodeLimit,
	IncompleteTextPartLimit,
	IncompleteTextPartByteLimit,
	IncompleteMultipartBoundaryLimit,
	IncompleteMultipartPartLimit,
	IncompleteMultipartHeaderLimit,
	IncompleteMultipartTextLimit,
	IncompleteMultipartParseError,
	IncompleteMultipartUnknownField,
	IncompleteMultipartTextFieldTypeMismatch,
	IncompleteToolSchema,
	IncompleteDeferredTextCandidateLimit,
	IncompleteUnsupportedMediaType,
	IncompleteUnsupportedContentEncoding,
	IncompleteRawBodyLimit,
	IncompleteRPCBodyLimit,
}

func (r *Result) IsComplete() bool {
	if r == nil {
		return false
	}
	return r.Completeness == CompletenessComplete &&
		len(r.IncompleteReasons) == 0 && !r.Truncated && r.ParseError == ""
}

func (r *Result) HasIncompleteReason(reason IncompleteReason) bool {
	if r == nil {
		return false
	}
	for _, existing := range r.IncompleteReasons {
		if existing == reason {
			return true
		}
	}
	return false
}

func (r *Result) addIncomplete(reason IncompleteReason) {
	if r == nil || !knownIncompleteReason(reason) || r.HasIncompleteReason(reason) {
		return
	}
	r.Completeness = CompletenessIncomplete
	r.Truncated = true
	rank := incompleteReasonRank(reason)
	insertAt := len(r.IncompleteReasons)
	for index, existing := range r.IncompleteReasons {
		if incompleteReasonRank(existing) > rank {
			insertAt = index
			break
		}
	}
	r.IncompleteReasons = append(r.IncompleteReasons, "")
	copy(r.IncompleteReasons[insertAt+1:], r.IncompleteReasons[insertAt:])
	r.IncompleteReasons[insertAt] = reason
}

func (r *Result) finish() {
	if len(r.IncompleteReasons) > 0 || r.Truncated || r.ParseError != "" {
		r.Completeness = CompletenessIncomplete
		return
	}
	r.Completeness = CompletenessComplete
}

func knownIncompleteReason(reason IncompleteReason) bool {
	return incompleteReasonRank(reason) < len(incompleteReasonOrder)
}

func incompleteReasonRank(reason IncompleteReason) int {
	for index, candidate := range incompleteReasonOrder {
		if candidate == reason {
			return index
		}
	}
	return len(incompleteReasonOrder)
}
