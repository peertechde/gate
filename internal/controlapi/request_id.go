package controlapi

import (
	"net/http"

	"peertech.de/gate/internal/requestid"
)

func ensureRequestID(w http.ResponseWriter, r *http.Request) string {
	return requestid.Ensure(w, r)
}
