package controlapi

import (
	"net/http"
)

type apiError struct {
	status  int
	code    ErrorCode
	message string
	details map[string]any
}

func writeError(w http.ResponseWriter, r *http.Request, err apiError) {
	requestID := ensureRequestID(w, r)
	var details *map[string]any
	if err.details != nil {
		details = &err.details
	}
	response := ErrorResponse{
		Code:      err.code,
		Message:   err.message,
		Details:   details,
		RequestId: requestID,
	}
	writeJSON(w, r, err.status, response)
}
